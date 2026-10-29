# Changelog

What changed in each release, newest first: a section for each, an alpha, a beta or a release candidate as much as
a final release. An alpha (`0.1.0-alpha.1`) is for trying a version early: it may still change before that
version is released. A beta (`0.1.0-beta.1`) is the version complete enough to use before it is released: it may
still change where using it shows a need. Before 1.0, a minor release (0.2.0) may change the policy language, the
`authz.*` functions, the SDKs and the file formats: what to do about it is under **Upgrading**. Each release from
0.1.0-beta.1 on upgrades from the one before it. How releases are numbered and made: [RELEASING.md](RELEASING.md).

## Unreleased

## 0.1.0-beta.2 (2026-10-29)

### Changed

- The Python the npm packages bring is CPython 3.13.18 (python-build-standalone 20261026), where it was 3.13.17.
- `authz.cancel_request` writes a line in the audit trail (`cancel_request`, the request's object, relation and
  requester, and the request's id), as deciding a request does. Before, a withdrawn request left no trace there.
- An empty condition is refused (AZ102, "empty {} condition") in a type's or a link table's `where`, a `shared if`
  and a caveat, as it already was in a permission or a rule. An empty `where` or `if` was read as none, so the type
  or the relation took more rows than meant; an empty caveat compiled to SQL that Postgres refused on apply. A
  policy that has one: write the condition, or take the `where {}` (or `if {}`) away.

### Fixed

- A condition that calls a function or an operator of the app's (`{not app.blocked(this.id)}`) runs with the
  policy's rights where a view reads its permission too: another type's rule through an arrow (`file.open =
  doc.open`), a permission that inherits, a masked view. There it ran with the app role's rights, so a function
  reading a governed table saw only what the signed-in user may see: under a `not`, row-level security could
  show rows the policy refuses (`authz.can` and a type's own select rule were right); otherwise it hid rows the
  policy grants, and a function reading the permission's own table made every read fail ("stack depth limit
  exceeded"). Conditions written as subqueries were not affected.
- The npm packages that hold the command's Python name its licence `Python-2.0` in their `license`, where they
  said `PSF-2.0`: the licence file they carry is CPython's whole licence (the PSF, BeOpen, CNRI and CWI
  agreements), which SPDX names `Python-2.0`; `PSF-2.0` is only the first of them.
- `rowstile review` flags a `shared if` taken off or rewritten for one subject of a relation shared with several
  (`viewer : user shared if {...}` beside `viewer : team#member shared`). It compared the relation's conditions
  together, and a subject shared without one hid the change of another's. The flag names the subject there:
  "`doc.viewer` for `user`: its share condition changed".
- The review's GitHub action and GitLab template update only the comment their token wrote. They took the first
  one that starts with the review's marker, whoever wrote it: a person's comment starting so was overwritten with
  the review, or GitHub refused the edit and the job failed. Now theirs stays, and the review is posted beside it.
- The VS Code extension (0.1.4) stops the language server it was starting when `rowstile.command` changes, once
  that server has started. It was left running beside the new one, and each mistake was shown twice until the
  window was reloaded.
- `authz.view_as` in a session limited by scopes (an API key's, a JWT's) keeps those scopes. It gave the session
  the scope `read`, so a key whose scopes let it view as a user read everything that user may, beyond what the
  key itself was given. A session without scopes still views with `read`. The session's signature and a JWT's
  are now compared through their hashes, so the time a comparison takes says nothing of how much of one is right.
- `authz.explain` says to whom a custom role was given when it was given to `anyone`, to every signed-in user
  (`user:*`) or to a link: "a custom role given to anyone (by 1) (role reader)". It said "a custom role given to
  (by 1)", naming nobody.

## 0.1.0-beta.1 (2026-10-22)

### Added

- `cascade from schema.table` under a table's rules says that its foreign key to that table deletes or changes its
  rows as meant (`ON DELETE CASCADE`, `SET NULL`, ...), and applying no longer warns of it. Where several keys
  to that table act, the line names the key's columns: `cascade from app.users (owner_id)`. Applying refuses a
  line that names no such key, or several (AZ625); a column it names that the table doesn't have is said as such
  (AZ601). The review flags a line added, `rowstile fmt` lays it out, and the editors highlight it.
- Versions have a beta stage, `X.Y.Z-beta.N` (on PyPI `X.Y.ZbN`), after the version's alphas and before its
  release candidates. The command orders versions so when it refuses to apply, push or migrate over what a
  newer version wrote (AZ616), and `rowstile init` asks a Python app for at least the beta it runs
  (`rowstile>=0.1.0b1`).
- Codes for the mistakes `rowstile init` and `rowstile snapshot` report, each with its page (`rowstile help
  AZ621`): AZ620 (no tables to draft from), AZ621 (which table holds the users), AZ622 (a users table the draft
  can't use), AZ623 (too many people for a snapshot).
- `rowstile review --out FILE` writes the pull request comment to FILE as well, beside what it prints:
  `--annotations --out review.md` gives both from one review. The GitHub action runs the review once this way,
  where it ran it twice (the base's tests and the access comparison too).
- The command's image (`ghcr.io/rowstile/rowstile`) is built for arm64 as well as x64: on an Apple Silicon Mac
  or an arm64 machine, Docker runs it without emulation. Its label `org.opencontainers.image.version` says its
  version, and it comes with its provenance, signed through Sigstore by the release workflow that built it:
  `gh attestation verify oci://ghcr.io/rowstile/rowstile:<version> --repo rowstile/rowstile` checks it.
- The Next.js page has a part on Next.js with pg, without Prisma. The reference names the columns
  `authz.list_shares` returns.

### Changed

- The beta starts afresh: it doesn't upgrade a database an alpha made, and no longer reads the names from before
  the rename (`rowfence.toml`, `ROWFENCE_PYTHON`, the marks rowfence wrote). Apply the policy to a new database,
  or to the same one after `rowstile remove --yes` (shares and history stay).
- The example apps (the file manager, the messenger) and the conformance apps (FastAPI, Next.js) each have one
  migration for their policy, written by this version's command: they kept every migration since the first
  alpha, about 45 each. The file manager's tables are one migration too, and the conformance apps no longer set
  `jit = off` on their app role (the sign-in turns JIT off for its own transaction). A database one of them made
  before is made anew: `docker compose down -v`.
- The Python package's extras ask for the versions its conformance suite runs on: FastAPI 0.110, asyncpg 0.29
  and psycopg 3.1.4 or newer (they allowed FastAPI 0.100, asyncpg 0.28 and psycopg 3.1, which nothing ran). The
  suite also runs each night on the oldest versions the extras allow.
- `rowstile review` says "Meaning unchanged: no declaration changed" when no declaration of the policy changed.
  It said "unchanged (only comments, spacing or order)", also on a pull request that didn't touch the policy.
- The VS Code extension (0.1.3) is no longer marked a preview on the Marketplace and Open VSX, and asks for VS
  Code 1.82 or newer, the oldest its language client runs on (it said 1.75).
- The npm packages ask for Node 22.12 or newer: the `rowstile` command said Node 18, and the TypeScript SDK's
  packages said nothing. The SDK's peer ranges name the majors its checks run, no longer any later one:
  `@rowstile/next` Next.js 16 (it said 15 or later), `@rowstile/react` React 19 (18 or later), `@rowstile/prisma`
  Prisma 7 (7 or later), `@rowstile/postgres` postgres.js 3 (3.4 or later), each from the version the checks ran.
- The npm packages with the command's Python are about 10 MB smaller each (`@rowstile/cli-linux-x64`: 15 MB to
  download, from 26). They no longer carry `libpython` (on Linux and macOS the Python is linked statically and
  never loaded it), `python3.13-config`, or the `dbm` module's C part (Berkeley DB on Linux), which the command
  never uses. Their `license` names the licence of each library in that Python, beside Apache-2.0 and PSF-2.0,
  and they carry those texts only.
- `rowstile init` drafts a team inside a team as nested membership: the members of the teams inside count as
  members of the team above (`member : team#member = app.teams(parent_id -> id)`), where the draft passed the
  team above's view down. A comment says the other reading. For teams, groups, orgs, departments and the like;
  folders still pass their view down.
- `rowstile init` adds to `package.json` only what the app needs to run, and says why each: `@rowstile/react`
  and `@rowstile/vitest` are named, not added.
- `rowstile init --db URL` in an app whose `DATABASE_URL` (in the environment, `.env` or `.env.local`) is another
  connection, often the app's, as its role, writes `database = "env:ROWSTILE_DATABASE_URL"` in `rowstile.toml`,
  and says to set it to the owner's. It wrote `env:DATABASE_URL`, and the next command connected with the app's
  URL. With `--db`, the line `found ..., Postgres` no longer says the connection came from `DATABASE_URL`.
- The command refuses an option the command doesn't take, naming it, exit 2: another command's (`check --force`,
  `apply --check`, `migrate --development`), `--db` on `check`, `prove`, `fmt` and `migrate`, which read no
  database, and one written with a single dash (`check -x p.authz` blamed the policy file). Each was ignored
  without a word. `rowstile graph` and `rowstile client` with `--db` read the policy in force on that database,
  not the file `rowstile.toml` names, and refuse `--db` beside a policy file.
- `rowstile --help`, `-h` and `help` print the usage on stdout, for a pager or `grep`; `--help` after a command
  that doesn't exist says so, exit 2. A command short of an argument says how many it takes, and shows its
  usage.
- TypeScript: `Problem`, what `problemOf(e)` returns, types its fields (`table`, `command`, `why`, `code`
  besides `status`, `type`, `title`, `detail`), so a field it hasn't, such as `p.body`, is a type error.
- The generated Python client's `share` takes `caveat_args` as a dict, `{"ip": "10.0.0.7"}`, as the TypeScript
  client's `caveatArgs` and `explain_rule`'s row do (it took JSON text). Regenerate the client.
- `rowstile.sqlalchemy.why_stale(exc)` and `why_stale_sync(exc)` take the `StaleDataError`, which they no longer
  may leave out: the SDK asks the database why a flush failed before its transaction is rolled back, and puts the
  answer on the error.
- `rowstile.sqlalchemy.install(engine, user=...)` given a `user()` for an engine installed without one (as
  `Rowstile(app, engine)` installs it) takes it, where it was ignored. Another `user()` than the one the engine
  has is a `ValueError`, where the first one stayed without a word.
- In `rowstile.testing`, a test that never awaits what `assert_refused` or `assert_not_found` returned for an
  async function fails at teardown and says to await it. It passed without checking anything.
- The operations page (Behind a pooler) says what runs every night: both SDKs' conformance suites with the app's
  connection through PgBouncer in transaction mode, keeping prepared statements. It asks for the command and
  migrations on the direct URL or a pooler in session mode, as the change feed (it said they ran through a pooler
  too), and says when Supavisor, PgCat, Neon and Supabase were tried by hand.
- The speed figures on the limits page and the benchmark's page say what measured them: a build of 2026-10-03,
  on the laptop the project was developed on then. No build since has run those sizes.
- The Python the npm packages bring is CPython 3.13.17 (python-build-standalone 20261021, with OpenSSL 3.5.9),
  where it was 3.13.15.

### Removed

- `rowstile review --json` no longer has `tests.invariants_removed`, which nothing printed: Risk's flag "an
  invariant removed" names each one.
- The Python SDK's helpers that its modules share are no longer public names: `rowstile.literal`,
  `call_problem`, `check_problems`, `key_text`, `key_shown`, `explain_rule_args`, `explain_rule_sql` and `answer`
  now start with `_`, and `key_text` and `key_shown` are one. `verdict()` and the rest of `rowstile.__all__` stay.
- A test's name is written in double quotes only, as the docs show it: `test "owners see their folders"`.
  `test owners see their folders` and `test 'owners'` are refused, with the line to write instead (AZ101), and
  VS Code no longer colours them as a test's name.
- The parser no longer knows `update cols check :`, the old way to write `update cols after :`. A column named
  `check` is now a column like any other: `update check : seal` is a rule on it (it was refused, with advice to
  write `update after :`). The review and the error pages no longer speak of `role x`, `roles : ... grant` or
  `check`. In VS Code, `check` in a rule is no longer coloured as a word of the language, and an `app role` line
  typed under an indented one moves back to the margin, as a `type` line does.
- The SDKs read an error's code (`error_code()`, `errorCode()`) from `rowstile help AZnnn` in its hint alone: no
  longer from `[AZnnn]` at the end of a message, which only errors from applying a policy carry.
- The command no longer takes names no doc gave: `-d` for `--db`, `rowstile version` (`--version`),
  `rowstile help codes` (`help errors`), `--as nobody` and `--as ""` (`--as anyone`), and `python`, `typescript`
  and `ts-sdk` in `[clients]` in `rowstile.toml` (`py` and `ts`).

### Fixed

- The app role reads none of rowstile's views, and of the rules' functions it calls only those that explain them.
  It could read views and call functions that told what the rules hide: with `can view = folder.view and not
  {confidential}` on files, the view of `folder.view` on files listed the confidential files in the folders a user
  may view; with a deny inside inheritance (`(viewer or parent.view) and not hidden`), the view of what the
  permission gives before the deny listed the hidden folders shared with the user, and its function answered for
  any folder; a condition that reads another table answered for any row the caller made up. The views and functions
  the rules use are now in `authz_int`: the rules use them, and the app role can't name them (Postgres keeps a rule
  as it was read when the policy was applied, and checks a schema's privilege only when a name is looked up). The
  rules' explanations (`authz.explain_rule`, the message of a refused write) answer for a new row or one the user
  may select, and say no to all of it for any other. A rule on a column is checked in its trigger's `WHEN`. Code
  that read an `authz_gen` view now gets `permission denied`: `authz.list` answers what it asked.
- A rule condition with a quote that Postgres reads as part of a string or a name (`E'it\'s'`, `$$it's$$`,
  `"o'neil"`) before a subquery now runs with the policy's rights, as any condition that reads another table
  does. The quote was read as the string's end, the subquery was missed, and the condition ran as the app role:
  through the other table's row-level security, a `not exists` there could show rows `authz.can` refused. The
  check that inheritance doesn't depend on the time missed `now()` after such a quote too.
- A rule's condition that calls a function of the app's named with a letter past ASCII (`{not app.muté(this.id)}`)
  runs with the policy's rights, as one calling `app.muted` does. It was read as no call, so the app role ran
  it, and the function read other tables through their row-level security: the app role could see rows
  `authz.can` refused.
- Where the SDKs write the sign-in into the statement (Python: the asyncpg adapter, SQLAlchemy with a driver of
  another parameter style, `act_as_sql()`; TypeScript: `actAsSql()`), an id holding a backslash stays one
  string when `standard_conforming_strings` is off. An id such as `x\'); SELECT ...` ended the string early, and
  the rest ran as SQL. Such a value is now written `E'...'`, its backslashes doubled.
- A statement on a partition, or on a table that inherits, runs the triggers of the table above. Moving a
  folder through a partition of the folders' table (a tree's table without rules), adding a link row to a
  partition of a link table, or changing a row a condition reads there left the inheritance tables and shares as
  they were, so users kept seeing what the move took away. Each partition and table that inherits now gets the
  triggers; `authz.lint()` names one made since the policy was applied, and the app role's TRUNCATE on a
  partition of any table rowstile watches.
- `authz.revoke_link` judges a link given in several relations as things are before it goes, and turns it off in
  all of them or in none. It took the link out of one relation at a time and judged the next on what was left: a
  user whose access came by that link was refused in the second relation once the first was gone, and taking it
  from the first could let a user turn it off in a relation they could not unshare when they asked.
- `authz.explain` with the signed-in user's own id answers as without one. For a folder user 3 can't see,
  `authz.explain('folder', 6, 'edit', '3')` as user 3 showed its rule and the parts it reads (`parent is a
  folder you can't see`, `yes  {inherit}`), where a missing folder showed none of that; it now says
  `no   you have no access to folder 6`, as for a missing one. Explaining another user's access with a scoped
  key now needs a scope that names the permission, as `authz.who` does, and reads that user's access with
  their full rights, not the key's scopes.
- `authz.explain` says "you" to a service signed in as itself, as it does to a user: a relation from a column
  read `bot: bot_id is` and stopped there, and a share `viewer: shared with`. It now says `bot: bot_id is you`.
- `authz.who` asked about an id that isn't one of the type's (`authz.who('doc', 'abc', 'view')` for a numeric
  key) put back neither the caller's scopes nor its principal type, nor signed again, so the rest of the
  transaction ran as someone else or, for a role that isn't the policy's owner, was not believed (AZ702).
  `authz.explain` for another user left that user signed in the same way. Only administrators get that far
  (the app role may not inspect such an id): both now put the caller back, as they do for any other id.
- A user whose id holds `:` or is `nobody` is now written `user:<id>` (`user:service:1`) wherever rowstile names
  who acted, and reads back as that user: in the SDKs (`Principal.parse(str(p))` in Python,
  `parsePrincipal(describe(p))` in TypeScript), the audit trail, `created_by` (shares, links, custom roles,
  reviews), `decided_by` (requests, reviews), what `authz.login_key` and `authz.login_jwt` return, the
  invariants' `user_id` and `rowstile diff` (its rows and `--users`). The user whose id is `service:1` was written
  `service:1`, as service 1 is, and read back as service 1; the user whose id is `nobody` came back as nobody.
  Other users are still their id (`42`), and other principals `type:id`.
- The decision log (`authz_debug.log_decisions`) named a service by its bare id, as if it were the user with that
  id. It now names who asked as the audit trail does: `service:7`, `user:service:1`.
- Every `authz.*` function that takes an object's id now takes it as the key's type too, as `authz.can` did:
  `authz.share('folder', 1::bigint, 'viewer', 'user', some_uuid)` said "function does not exist" where users
  have uuid keys, and so did `unshare`, `create_link`, `create_role`, `roles_of`, `request_access`,
  `break_glass` and `start_review` given a uuid. A policy whose keys are all text no longer gets their bigint
  versions.
- `authz.roles_of('org', '007')` listed none of org 7's roles: it compared the id as written, where
  `authz.create_role` stores it as `7`. It now reads it as `authz.can` does.
- `authz.decide_request()` with nobody signed in (a backend that forgot to sign in, an operator in psql) said
  "you cannot decide your own request". It now says "sign in to decide a request" (AZ714, a 401 in the SDKs).
- `authz.sync_members()` given NULL for the list removed every member of the group (a sync job's failed fetch
  emptied the team), and a NULL in the list failed with Postgres's not-null error from the app's table. Both are
  now refused, saying to list the members with no NULL (AZ710, a 400 in the SDKs); an empty list still means none.
- A mask that goes gives the app role back the SELECT it had on the column. Where the app role read the table
  column by column (`GRANT SELECT (id, body)`) and a mask took `body`, removing the mask, by applying, by a
  migration or by `rowstile remove`, left `body` unreadable: only a table-wide SELECT was given back. And a
  table-wide SELECT given back by applying no longer leaves beside it the column grants the mask gave instead.
- An app role named with capitals works. `app role AppUser` names the role `"AppUser"`, as written, as a
  table's name is. The rules and grants went to `appuser` (Postgres reads an unquoted name in lower case),
  while masks and the named tests looked for `AppUser`, and failed with "role ... does not exist".
  `authz.connection_check()` didn't find a connection's role named with capitals, and said nothing of it.
  `rowstile init --role AppUser` quotes the name in the `CREATE ROLE` it says to run. A policy that names a
  role made without quotes (`CREATE ROLE App_User` makes `app_user`) writes it in lower case.
- An app role that is the policy's owner, or a member of it, was not reported: its sessions are believed without
  a signature, and it may read rowstile's tables and turn row-level security off. Applying now refuses an app
  role that is the role applying the policy, or a member of it (AZ624), where applying as that role stopped on
  `permission denied for table masked_columns`. `authz.lint()` and `authz.connection_check()` report one that
  became a member since.
- `authz.lint()` and `authz.connection_check()` said nothing of an app role that owns a governed table once the
  table had `FORCE ROW LEVEL SECURITY`, which lint's own message advised. An owner may turn row-level security
  off again: both now report it either way, and lint says the app role must not own the tables.
- Applying and `rowstile remove` know rowstile's own row-level security policies by the comment that marks
  them, not by their names. An app's own policy named `authz_select` (or `authz_insert`, `authz_update`,
  `authz_delete`) was dropped as rowstile's, without a word, and `authz.lint()` didn't report one on a governed
  table. Now it stays, and lint says it isn't rowstile's.
- Applying warned only of foreign keys `ON DELETE CASCADE` on a table with rules. It now also warns of `ON DELETE
  SET NULL` and `SET DEFAULT`, and `ON UPDATE SET NULL` and `SET DEFAULT`: Postgres runs these without row-level
  security too, so deleting a row (or changing its key) can change rows the user may not change. The warning says
  which action and what it does, and asks for `RESTRICT` (where it said `ON DELETE RESTRICT`) or a `cascade from`
  line. `ON UPDATE CASCADE` stays quiet: the row still names the same row.
- `rowstile remove` left the app role its USAGE on schema `authz` and its EXECUTE on `authz.ctx` and
  `authz.link_hashes`, which applying gives. It now takes them back: after removing, every privilege is as it
  was before the first apply.
- `rowstile remove` ran over a policy a newer version of rowstile applied, though an older command doesn't
  know everything a newer one makes and would leave some of it behind. It is refused now (AZ616), as `apply`,
  `push` and `migrate` are, unless told `--downgrade`.
- The command said "no policy is applied" (AZ609) whenever the database lacked an `authz.*` function it called,
  though a policy was applied. Now that message is only for a database without one. A policy another version of
  rowstile applied, without the function as this command calls it, is said with that version's name and
  `rowstile reapply` (AZ626, new), or "upgrade the rowstile command" when that version is newer (AZ616). A name
  rowstile doesn't make, or arguments no function takes (a typo in `rowstile sql`), is said in Postgres's words.
- A new version of rowstile that changes only what the app role is granted, or only an inheritance tree's
  functions (a message, an error code), is the next migration. Before, `rowstile migrate --check` said there was
  nothing to do, and a database set up by its migrations kept the old grants or messages. A tree's functions are
  replaced in place: the tree keeps its rows.
- A schema migration can drop a column no rule reads from a table with write rules. After the policy was applied,
  Postgres refused to drop any column of such a table ("cannot drop column ... because other objects depend on
  it"), and its hint, `CASCADE`, would have dropped the table's insert and update policies. The functions that
  explain a refused write, and the policies that call them, named every column of the row; now they pass the
  whole row and name only the columns the rules read. A column a rule reads still can't be dropped before the
  policy stops reading it.
- Inheritance trees whose names are longer than Postgres keeps (63 bytes; the tree is named after its types and
  relations) work like the others. A migration that rebuilt one whose conditions read another table failed
  ("cannot drop desired object(s) because other objects depend on them"), and one that swapped in a tree built
  beside failed ("already exists"). Applying rebuilt such a tree each time, under its lock, where it keeps the
  others that didn't change. And `rowstile indexes` advises a name Postgres keeps for an index on long names, so
  it finds, and says to drop first, what a failed `CREATE INDEX CONCURRENTLY` of it left unfinished.
- In a tree whose inheritance conditions read other tables (`{not exists (select 1 from app.frozen ...)}`), every
  statement on the tree's own table checked those conditions again on every row of the type, under the type's
  lock: renaming a folder waited for a folder's move in another transaction. Such a statement now checks them again
  only when a condition reads that table itself (the folder above's columns, say), and only if it wrote a row.
- In a tree of several types, moving a link in its table (an `UPDATE` of a placement) refreshed what was below the
  new link, then what was below the old one: twice the work, and two entries in the change feed. It is done once.
- A condition with a string or a comment that names `authz.uid()` (`{note <> 'set by authz.uid()'}`) compared
  with another string in `authz.can`, `authz.list` and the rules: rowstile rewrote the call inside the string
  too. Only the condition's code is rewritten now.
- A condition that names a column of its row in two cases (`this.ID` and `this.id`) inside a subquery failed
  with `column reference "id" is ambiguous`. Both are one column now, as Postgres reads unquoted names.
- A condition that limits inheritance and reads another table could call `age(x)` with one argument, which
  counts from today: the stored inheritance went stale without a word. It is refused (AZ305), and so are
  `current_schema`, `current_catalog`, `current_database()`, `system_user`, `random_normal()`,
  `gen_random_uuid()`, `uuidv4()`, `uuidv7()`, `authz.principal()`, `pg_backend_pid()`, `txid_current()` and
  `pg_current_xact_id()`. The language reference and AZ305's page list all it refuses. A column named like one
  of these functions (`now`, `random`) is no longer refused.
- Conditions and tests that name a column with a letter past ASCII, unquoted, read it as Postgres does
  (`{not archivé}`, `SELECT année FROM ...`): `rowstile apply`, `migrate`, `push` and `test` stopped with a
  Python traceback (`AssertionError`), and nothing was applied. `this.étage` names the row's column (applying
  stopped: `missing FROM-clause entry for table "this"`), the hint for `d.archivé` names the whole column (it said
  `d.archiv`), the warning on a bare `archivé` that a subquery's table takes is given (it was missed), and
  `ARCHIVÉ` is the column `archivÉ`, as Postgres folds only ASCII letters to lower case.
- `{size > ٣}` compared size with the number 3; Postgres reads `٣` as a column's name. Only the digits 0 to 9
  make a number now.
- A condition may hold `/* ... */` comments, as Postgres reads them (nested, over several lines): an apostrophe
  or a brace in one was read as a quote or the condition's end, and the policy refused with "a { condition is
  missing its closing }". A `$` inside a name (`total$$`) no longer opens a dollar quote either.
- Parentheses that change nothing no longer get an inheritance refused. `can view = owner or (parent.view or
  owner)`, or `((owner or parent.view) and {inherit}) and not hidden`, was refused as depending on itself (AZ302)
  or as narrowed with more than conditions (AZ304). They are now read as if the parentheses weren't there.
- A deny may inherit on the same conditions as the permission it takes away, written in another order, or on
  fewer of them: `can hidden = ... or (parent.hidden and {inherit})` beside `(parent.view and {not archived} and
  {inherit})` is taken. Where its conditions differ otherwise (`{INHERIT}` for `{inherit}`), the message shows
  both: it said the deny must inherit through `parent`, which it did.
- A mistake after the first word of a line at the left margin says how that line is written:
  `type folder app.folders` gets "write types as: type name = schema.table [(key)] [principal] [where {sql}]", and
  `include roles.authz` is told to put the file's name in double quotes. Each such line was told it didn't start
  with `app role`, `type`, `rules`, ... although it did.
- A permission line takes a tab after `can`, as every other line takes one between its words. It was read as a
  relation and refused ("write relations as ..."), and `rowstile fmt` refused the file.
- A block ends at an include line and at the end of its file. An included file's first lines, indented, went on
  with the block before the `include` line, and indented lines after it with the included file's last type: they
  are now refused as outside a block. An indented `include` line says it must start at the left margin (it was
  refused as a relation).
- A missing included file is reported as `can't find teams.authz in the policy's folder`, with the name it
  looked for from the policy's folder. The command said to "pass it in the files argument", which it has no
  such thing as.
- A policy that includes a file named with an apostrophe (`include "o'brien.authz"`) failed to apply with
  a bare syntax error. It applies, and the messages that name the file's lines say its name as written, a `%` in
  it too. A file whose name holds a dollar quote's tag (`$f$`) can't be included: the include line is refused,
  saying to rename the file (AZ108).
- A test line names a scope as the `scope` line declares it: `with scope files:write` and `with scope read-only`
  were refused ("a test's lines are ..."). The editors read such names too.
- A test with an empty name (`test ""`) is refused, and words after a test's closing quote are said to be the
  mistake (it said the quote wasn't closed).
- `as ... sees N {...}` refuses a statement that writes after a comment or in its `WITH`
  (`WITH gone AS (DELETE ...) SELECT ...`), as it refuses one that starts with `DELETE`. `rowstile test` failed it
  with Postgres's error.
- `rowstile check` (the MCP server's `check` too) and the editor report a mistake in the policy's own test
  lines, as `rowstile test` does: a test naming a type, a permission or a scope the policy doesn't have read as
  `ok` there.
- Error pages and messages say what the compiler does. AZ302 no longer calls a permission inheriting across
  types (projects and folders inside each other) a mistake; AZ306 says conditions may join the inheritance
  beside the deny; the error codes' index says that an error the app meets at run time carries its code in its
  HINT, not at the end of the message. AZ502 names the types that sign in without "one of" a list of one, and
  messages no longer say "a org".
- `rowstile fmt` lays out a condition whose string, quoted name or dollar quote goes on to a line that starts
  with `--`: that line is in the quote, not a comment. fmt refused such a policy, saying formatting would change
  what it says. And a run of spaces inside a quote counts: the lock file's lines, and fmt's check that it
  changes nothing, read `'a   b'` and `'a b'` as two things.
- `rowstile prove`'s counterexample, and the world the review shows when a change is no refactor, say what the
  world holds as you would make it. A share to `user:*` read as a share to one user (`folder 1 -> user 1`); it
  reads `folder 1 -> user:*`. The rows each type's `where` keeps are said (`{active} holds for user 1 (the type's
  where)`), and making the world smaller no longer takes away the value a kept row needs (`active = true`): the
  user shown looked suspended. The custom roles given are listed (`doc.roles with view: doc 1 -> user 1`), and
  `anyone` reads `anyone`, not `anyone *`. The review's world is made as small as it still grants otherwise in,
  as prove's is: no link that plays no part. "after 1 worlds" reads "after 1 world".
- `rowstile prove` and the review read two texts compared with one column as two values, so
  `{status = 'Public'}` and `{status = 'public'}` never held on one row there. A column under a case-insensitive
  collation holds both, and prove said an invariant held that the data broke. Texts a column may hold as one
  value (the same but for case, accents, spaces or punctuation; two that name numbers or dates; letters past
  ASCII) are now left to the database there, as a subquery is: prove draws the rows each holds for, and the
  review says it can't compare a change between them. Different words (`'draft'`, `'published'`) are still read
  as two.
- `rowstile review` flags more of what widens access. A rule that reads a relation's permission itself
  (`insert : folder.edit`) changes through that relation, as `select : view` does: repointing `file.folder` to
  another column now flags who may insert. A `shared if` removed or changed, and a caveat changed, are flagged.
  A plain `update after` removed is no longer called a column rule: it is flagged where the `update` rule, which
  then checks in its place, lets more rows through; a new one is flagged where it lets more through than
  `update` did.
- `rowstile review`'s Deploy names the tables a migration finds only as it runs, and the mode it locks them in:
  the tables an inheritance condition reads, and the partitions and child tables of the governed ones. It said
  "Locks `app.folders`" while the migration also locked `app.settings`, which a condition read.
- The comment `rowstile review --markdown` writes shows Meaning's example when a change thought a refactor isn't
  one: what differs, for whom, on what, and the world that shows it, as the text output says. A failed test
  without a line or a detail reads `- fails: a test`, not `- fails: a test : ` and two backquotes.
- `rowstile review` checks a change that looks like a refactor in seconds on a policy with many types. The small
  worlds it lists counted rows of every type, also those the change doesn't read: with 14 types, a permission
  rewritten as `owner or owner` took almost four minutes, and each more type about four times as long. Only the
  types the change reads vary now, and the listing gets further in the same number of worlds.
- The review's GitHub action passes on a pull request from a fork. GitHub gives such a pull request a read-only
  token, so the comment was refused and the job failed. Now the review is in the run's summary, and a notice
  says so.
- A review longer than a comment may be is cut, and the comment says where the whole review is: the run's
  summary on GitHub, the job's artifact on GitLab. GitHub refused a comment over 65,536 characters, and the
  GitLab job failed ("Argument list too long") on a review over 128 KiB.
- The GitLab template's header said a top-level `ROWSTILE_VERSION` picks another release. GitLab gives the job's
  own variables first, so it was ignored. It now shows how to set it, and the stage, in the job, and says to set
  `ROWSTILE_REVIEW_TOKEN` in the CI/CD settings, not in the file.
- `rowstile init` read the columns a primary key or unique index INCLUDEs as part of the key. A table with
  `PRIMARY KEY (id) INCLUDE (title)` was drafted as keyed by `(id, title)`: a users table so declared was refused
  (AZ622), and foreign keys to such a table gave no relation. `authz.lint()` likewise said the app role may choose
  a primary key the database makes when it may write a column the key's index INCLUDEs. Both read the key's own
  columns now.
- `rowstile indexes` and `authz.lint()` counted an index's INCLUDE columns as if the index were sorted by them.
  An index on `(parent_id) INCLUDE (parent_type)` was said to serve a lookup by `(parent_type, parent_id)`, so a
  lookup with no index could go unnamed. Only an index's key columns count now.
- `rowstile init` stopped with a Python traceback (`KeyError`) when the table the columns naming users point to
  wasn't among the drafted ones: in another schema (as Supabase's `auth.users`, with `--schema public`), or left
  out for its name. It now says which table, which columns point to it, and what to do: draft its schema too,
  or name the table with `--users`.
- `rowstile init` notes that a membership's `permission` or `permissions` column may say who does more, as it
  did for `role`, `kind`, `level` and `access`. `rowstile init --help` says it drafts from every schema of the
  app's when `--schema` names none (it said `public` only).
- `rowstile init --out` refuses an absolute path or one outside the folder, before writing anything (exit 2):
  every later command refused the `rowstile.toml` it wrote. A folder name holding `"` or `\` is written
  escaped, so `rowstile.toml` still reads.
- `rowstile init` finds goose, dbmate and Flyway: their markers in a migrations folder's files, Flyway's names
  (`V1__init.sql`), or the folder `flyway.toml` or `flyway.conf` names. It took them for plain SQL, and the
  files `rowstile migrate` then wrote were refused or skipped. Files named for a tool rowstile writes none for
  (`1_init.up.sql`) leave `[migrations]` out of `rowstile.toml`, and init says so. It reads Drizzle's
  `out: "../shared/drizzle"` as written (it read `shared/drizzle`, and a key ending in `out`, `layout:`, as
  `out`), and marks a migrations folder that is `rowstile.toml`'s own `/*_authz_*` in `.gitattributes`
  (`./*_authz_*` matched nothing).
- `rowstile migrate` for goose, dbmate and Flyway names its file with the number after the folder's last when
  that one is numbered (`00003_`, `003_`, `V3__`), as it did for plain SQL. It used the time, and the app's next
  migration, numbered after its own, then came below one applied already: goose, Flyway and `dbmate --strict`
  refused it. Plain SQL files take the time after a folder whose last file starts with the time.
- `rowstile sql --as WHO "COPY t FROM STDIN"` waited for good, with a transaction open on the server. The copy now
  fails at once: "COPY from stdin failed: the rowstile command sends no rows to COPY FROM STDIN (psql's \copy
  does)".
- An empty `--db` (a script's `--db "$DATABASE_URL"` with the variable unset) stopped with a Python traceback.
  It now says `--db is empty`, exit 2, as an empty value of any option does.
- The command connects as libpq does where it didn't. `sslmode=prefer` (the default) tries again without TLS when
  TLS fails (a `~/.postgresql/root.crt` that didn't sign the server's certificate) or the server refuses the
  session over TLS. `sslmode=allow` tries without TLS first. `connect_timeout=0`, or less, waits as long as it
  takes (it meant 10 seconds, and `-1` was refused). What still differs is named in the tools reference: no
  password file, 10 seconds where `connect_timeout` isn't given, and no client certificate.
- The command's connection messages: a port out of range (`postgresql://h:70000/app`, `port=0`) is said as such
  (a URL's was blamed on a `#` in the password). A password stays out of them: a refused setting that holds a
  secret (`scram_client_key`, `scram_server_key`, `oauth_client_secret`) is named without its value, and the rest
  of a password with a space in it, unquoted (`password=my secret`), isn't repeated. When the server asks for a
  password and none was given, the error says where to give one, and that the command reads no password file
  such as `~/.pgpass`.
- When the server closed the connection without a word (it crashed, a proxy dropped it) while a statement was
  on its way to it, the command said `lost the database: [Errno 104] Connection reset by peer`. It now says
  `lost the database: the server closed the connection`, as it does when the server closes between two
  statements. When the server said why first (the session was ended, it is shutting down), those words are
  still what the command says.
- The MCP server (`rowstile mcp`) answers a call whose arguments a tool refuses (one missing, null, or one that
  reads as an option, such as `--development`) with the tool's failed call (`isError`, exit code 2, the reason in
  its text), as MCP 2025-11-25 asks, so that the agent sees why and corrects the call. It answered with a protocol
  error, which a client may keep from the agent. A call whose `arguments` isn't an object is a protocol error now,
  where the tool ran as if it had none.
- The language server checks an open test file again when the policy changes: renaming a permission in the
  policy marks the test lines that still name it, where they kept their old diagnostics until the test file
  itself changed. A mistake in the policy, seen from a test file, is said on the test file's first line with the
  policy's file and line (`policy.authz line 7: ...`), where it sat on the test file at the policy's line. It
  clears a closed file's diagnostics, which an editor kept showing, and checks the open files again when the
  policy's file is closed with changes not saved. Find references searches the policy's included files and the
  open test files, not only the file it is asked in.
- The language server counts columns as editors do (UTF-16 code units): after an emoji on a line, hover,
  completion, go to definition and the underlined words were one column off. A message it can't read (a body
  that isn't JSON, a `Content-Length` that isn't a number) is answered with a parse error, and the server goes
  on. It ended, and the editor lost errors and completion.
- The editors read more policies as the compiler does. Zed, Helix and Neovim showed a parse error on a condition
  holding `"a}b"`, `"it's"`, `E'it\'s'`, `$$}$$`, a `/* } */` comment, or a `--` comment with a brace or an
  apostrophe in it; on a column named `before` or `after` (`update before before : edit`, as the compiler's own
  message suggests); and on a test id with a `$` inside (`user a$b can view file 1`). In VS Code and on the site,
  `before` and `after` at the end of an update rule's columns are coloured as words of the language, not as
  columns; `test` and `invariants` followed by a comment keep their colour; and `user:*` (any type's), `principal`,
  `include "roles.authz"`, a link table's name with its `object:` and `subject:`, and test lines whose id is
  quoted with a space are coloured. VS Code moves `type`, `rules` and the other first words back to the margin
  when typed on an indented line, and closes `[` and `"`.
- The VS Code extension builds from the repository as its page says (`npm run package` in `editor/`): it
  stopped on a missing `LICENSE`. The link on its Marketplace and Open VSX page, to installing the command, leads
  to that page again. When the language server doesn't start, the extension (0.1.3) says why, and how to install
  rowstile or set `rowstile.command`, where it only said it couldn't connect. A change to `rowstile.command`
  starts the server again with it; it needed a window reload.
- The editors' page says how to point VS Code and Zed at a `rowstile` installed in the project (npm's
  `node_modules`, a `.venv`): such an install isn't on the PATH the editor starts the server with. Its Neovim
  steps highlight: they now build the grammar, put it where Neovim looks and start highlighting, and say
  Neovim 0.11 or newer. Paths into the repository say `core/cli/`, and Sublime Text is no longer said to read
  the TextMate grammar as it is.
- Studio's grid showed a table's rows in the order of their ids as text: with numbered rows, 1, 10, 100, 101,
  ... 11, page after page. They now come in the key's own order, 1, 2, 3. Studio listed the tables, so two types
  over one table (a table with no rules may be read as several) showed as one, with one type's permissions under
  the other's name. It now lists the types, each with its table.
- In a Studio that can write (`--write`, `rowstile dev`), why and the access diff ran in a transaction that was
  committed, though each change they try is undone. They are now rolled back whole: nothing they try stays.
- `rowstile why` and Studio listed a change both as the best way to grant a permission and as "could not be
  tried", when the change grants it but counting what else it gives failed (a condition that fails on another
  row, say). It is now listed only as not tried, with the database's reason: what else it gives was never counted.
- Studio's page: in the Tables tab each row's cells sit under their headings again (each row was laid out as a
  flex box, its cells bunched apart from the columns). "Why?" while viewing as anyone says to pick someone,
  where it showed "Asking…" for ever. Clicking a type or a permission in the graph shows how it is written
  (nothing happened). The page asks for the policy again when a tab or a table is opened, so under
  `rowstile dev` a permission added or renamed since the page opened is offered. The shares show a custom
  role's name (not `role:<id>`), a caveat, and when a share starts; a request shows for how long approving
  gives it. A share link has no Unshare button: it removed nothing and said "Done". The page says
  `authz.revoke_link` turns a link off, and Studio refuses to unshare a link. The graph uses the playground's
  Mermaid (12.0.0), checked against its hash.
- The generated Python client named each type's permissions with its name in lower case after the first letter:
  `orgUnit` gave `OrgunitPermission`, and two types whose names differ only in case, `doc` and `Doc`, both gave
  `DocPermission`, the second replacing the first. A type's alias now keeps its name as written
  (`OrgUnitPermission`), and two types that would get the same one get none, with a comment that says why.
- Both SDKs read Postgres's own refusals for what refused. An update after which the user could no longer see
  the row was a 403 that spoke of reading an insert back; it now says the user may not see the row as written
  (the select rule). In Python, an upsert (`INSERT ... ON CONFLICT DO UPDATE`) of a row the user may not change
  named the select rule; it names the update rule, as in TypeScript. A `MERGE` that matched a row the update or
  delete rule hides was no refusal at all (a 500); it is a 403 with no command, since Postgres doesn't say which
  rule. And in Python a refusal by a restrictive policy rowstile didn't make is no longer read as the select
  rule's: it stays the database's error, as in TypeScript.
- TypeScript: inside `transaction(fn, who)` (`@rowstile/pg`, `@rowstile/drizzle`) and `begin(fn, who)`
  (`@rowstile/postgres`), the object's own calls (`a.expect`, `a.can`, `a.share`, `a.query`, ...) run in that
  transaction, as `who`, and `fn` acts for `who`. They ran in a transaction of their own on another connection,
  signed in as whoever the code around acted for (or the `user` function, or nobody): `a.expect` gave the reason
  for someone else, nothing saw what the transaction had written, and on a pool of one they waited for ever.
- `@rowstile/prisma` reads a compound key's fields in the key's order, which its name gives
  (`project_id_user_id`), not in the order the `where` lists them: `{ user_id: 2, project_id: 1 }` was asked
  about row `(2,1)`, so an update could be a 404 where it is a 403, or name the wrong row. A key given a name of
  its own (`@@id(name: ...)`) names no row unless `authz({ keys })` gives its fields.
- `@rowstile/drizzle` on node-postgres listens for a lost connection while a transaction holds one, as
  `@rowstile/pg` does: a database that restarts mid-transaction fails the transaction, where it stopped the
  process.
- `@rowstile/react` works in a Next.js server component, such as `app/layout.tsx`: the package is a client
  module (`"use client"`). Rendering `<AuthzProvider>` or `<Can>` there failed the build, which asked for
  `"use client"` in a file of the app.
- `rowstile.fastapi` with no engine, `Rowstile(app, None, user=...)` (an app on psycopg or asyncpg without
  SQLAlchemy), answers the drivers' errors as it answers SQLAlchemy's: a refused write 403, and each code as its
  page says. They were a 500.
- `rowstile.fastapi` answers an ORM update the rules allow that matched no row (the row changed since it was
  read: a version counter) with 409, where it answered 404 "the row not found". Where it can't tell (a model
  mapped to a join), it leaves the `StaleDataError` to the app.
- A refused ORM update is explained from the flush's own transaction, before it is rolled back. A row that
  transaction had written answered 404, since another transaction can't see it; with a pool of one connection
  that the request's session still held, the answer waited for the pool and failed with a 500. A flush of more
  than 20 rows of a table was asked about its last 20 only (a 404 when the refused row came earlier), one query
  each: every row is asked about now, in one statement.
- `NotFound()` without a table says "not found", and `NotFound(id_=7)` "row 7 not found" (it said "the row not
  found").
- `rowstile.alembic.include_object` said it left out the masked views rowstile makes. It leaves out a model whose
  table says so, `info={"rowstile": True}`: the FastAPI page and the SDK's README now say to mark a model of a
  masked view that way.
- The Python SDK's docs no longer offer `pytest_plugins = ["rowstile.testing"]`, which stops pytest once the
  package's entry point has loaded the fixtures. `ids()` says a uuid key takes `key_type=Uuid` (with `None` the
  ids are text, which a uuid column can't be compared with), and that a key of several columns can't use it.
- The npm launcher asks the Python `ROWSTILE_PYTHON` names for its version first, as it asks the one on `PATH`:
  one older than 3.11, or a path that isn't a Python, is refused with a sentence, where the command failed
  inside. A bundled Python that isn't executable and can't be made so (a `node_modules` another user
  installed) is said to be so, not to be missing. `ROWSTILE_PYTHON` has its line in Installing and
  Troubleshooting.
- The packages hold the command's files and nothing else: the npm package's build copied `core/authzlib` and
  Studio's folder whole, and the Python package's wheel and sdist took any file beside them, so a file left
  there (a note, an editor's backup) went in. Both now take the files one list names. A release publishes on
  PyPI and on the VS Code Marketplace the files its GitHub release attaches and attests (the wheel, the sdist
  and the `.vsix` were built a second time for those), and a patch to an older line no longer becomes the
  repository's latest release on GitHub.
- The tools reference lists every option each command takes (`migrate --tool --dir --one-phase --downgrade`,
  `diff --limit`, `bench --people --rounds`, `init --role --out`, `snapshot --out`, and the others), every
  `rowstile.toml` setting (`[migrations] lock` and `write_after`, `[review] snapshot`, `[clients] ts`), the exit
  codes, and which folder `migrate --dir` and `--out` are read from. `rowstile --help` names `review`'s policy
  argument and `[review] snapshot`, and says which policy `graph` draws.
- The reference's list of the generated Python client's calls left out `sign_in_as`, `principal`,
  `connection_check` and the API key calls, and it said the TypeScript client had the same calls, which it
  doesn't quite (no `principal`, signing in with `asUser`). It now lists each client's calls, and which calls the
  TypeScript SDK has. Its table of functions names `authz.perms_of` and `authz.connection_check`.
- The policy language page's example applies as written: its `shared if` condition had `...` in it, which no
  database runs. It says what an include may name (a file in the policy's folder, once). The identity page and
  the threat model name `view_as` among what signs a session in; the identity page no longer says the SDKs sign
  in with a key. The operations page says to make the roles first when restoring on a new server (`pg_dump`
  keeps none), and the OpenFGA and SpiceDB pages name the line their policy needs before its editors can be
  shared.
- The docs didn't say that a write rule checks each row against the tables as the statement found them, so a
  count in a rule is no limit on how many rows there may be: with `insert : {(select count(*) ...) < 2}`, one
  `INSERT` of three rows writes all three. The limits page says so now, and what to use instead (a unique index,
  or a trigger). The messenger example relied on such counts: one `INSERT` could put three people in a direct
  chat, or two owners in a new group. Its schema now holds both.
- The stack pages' code no longer takes the signed-in user from a request header. The Next.js and FastAPI
  pages showed the conformance apps' stand-in, a header any client can set; they now show the user coming
  from the app's session (`auth()` in Next.js, the app's own `session_user` in FastAPI). The Next.js page's
  install line has `@rowstile/pg`, which its live updates import, and the FastAPI page's code imports `os`
  and `rowstile`, which it uses.
- Three cookbook recipes gave more access than their pages said. In roles per organization, a document's owner
  could move it into another organisation, or make one there, and its members saw it: its organisation now
  can't change (`update org_id : nobody`). In tenants, a ticket assigned to someone of another organisation was
  theirs to read and edit: the assignee now holds it only as a member (`(assignee and org.member)`), and an
  invariant says no one outside sees a ticket. The multi-tenant page says that someone in two organisations may
  move a project across, and how to forbid it. The language reference says which moves `authz.lint()` warns
  about. A policy copied from these recipes wants the same change.
- Each cookbook page said to take the recipe's files and run `rowstile dev`, which stopped at "which policy
  file?". Each recipe's folder now has a `rowstile.toml` that names its policy and its tests, and the cookbook
  says the steps: load `schema.sql` and `rows.sql`, then run `rowstile dev`. The recipes' tests now check what
  their pages say: someone with a link sees the document, a share starts and ends when it says, an approved
  request ends after the time asked for, nobody decides their own request, asking for a document that doesn't
  exist goes as asking for a hidden one, a private folder's owner keeps it, and teams count three deep and in
  a loop. `rowstile dev --help` shows that it takes a policy file.
- The page on files in S3-compatible storage (`docs/signed-urls.md`) uploads as the file manager does: the browser
  sends the bytes to a place of their own (`uploads/<key>`), and confirming the upload moves them to the file's
  object and checks their size. The page signed the upload for the object's own key: that link goes on working
  after the confirm, so it could replace a confirmed file, whose stored size was then wrong.
- The docs app's own tests (`core/example`) pass on its own data, as their header says: 3 of their checks needed
  shares that only the end-to-end scenario made, and are now a named test that makes them. The playground's docs
  example shows the policy's tests too.
- The playground goes on after an edit that follows an answer: the tests run again and the question is asked again.
  It stopped there for good, and Run did nothing until the page was reloaded. A step that fails no longer stops the
  ones after it, and an answer with a large `int8` in an array (`ARRAY[9007199254740993::int8]`) shows. Asking after
  a failed run says the policy isn't applied, not that the last policy's role doesn't exist. An answer whose
  statement ran `COMMIT`, `ROLLBACK` or `RESET ROLE` says it wasn't rolled back, or which role it ended as (after a
  `COMMIT`, the rest ran signed in as nobody). The Help pane shows an error page's examples as code. A link the page
  can't read says so until another example is chosen, and a page whose `bundle.json` doesn't load says why, where it
  said "loading…" for ever.
- The site's links to the repository's files go to the release it shows, not to `main`, where a file may have
  moved or changed since. Its headings' anchors are GitHub's (`#what-a-0x-release-promises`), so a link to a
  heading written for GitHub finds it on the site too. The card a shared link shows is drawn with fonts kept
  beside it (Inter, JetBrains Mono), so it looks the same whichever machine renders it.
- The blog post's `experiment.sql` stopped at its first query when run by a role that isn't a superuser
  (`permission denied to set role "demo_app"`): it now grants that role to whoever runs it, so a role with
  CREATEROLE runs it on a stock server too. Its header says it drops an earlier `demo` schema and
  `demo_app` role first, and to read the middle of each query's three timings, as the post's figures are.
- The file manager example: its development steps work as written, as the messenger's do (the README waits for
  the services, runs the frontend from its own folder and says `npm ci`), and its README names each setting with
  its default, the maintenance jobs to schedule and each part of the backend. `migrate.py` runs outside this
  repository: it needs the command only for `--client`, and there it runs the one installed. The app's image no
  longer copies the command, and `test.sh` takes the database and storage down when a step stops the run early.
- The file manager example's rules and API: moving a folder takes the right to share it, as deleting it does (an
  editor could move a folder into one of their own, which gave them `share` on it and took it from everyone who
  reached it from above). Two uploads committing at the same time could together pass the storage quota; the
  second now waits for the first. `FM_MAX_UPLOAD_BYTES` holds for the bytes an upload sends, not only for the
  size it claims. Its errors say what is wrong, from the constraint's name ("the folder isn't empty" was said of
  a group with sub-groups and of a member who has no account). Search pages by name then id, each list with its
  own cursor: a page that ended among equal names skipped the rest of them. The app waits for RustFS to answer
  before it starts.
- The file manager's web app shows a file's Share, Rename, Move and Delete, a folder's Rename, and a file's
  "Upload a new version" and "Make current" only where the API says the user may (`can_edit`, `can_share` in
  each listing, from `authz.can`), and a folder's Share, Move and Delete only to those who may share it: they
  showed where they could only fail. Search
  shows "More" (it stopped at 50). A share link was listed twice in the share dialog. A share or link "until" a
  day lasts to the end of that day where the person is (it ended as that day began in UTC). A request's duration
  reads "7 days", not "P7D". Cancel on "Why not?" no longer denies the request, and a preview's Download or
  "Leave this group" that fails says why.
- The messenger example: its development steps work as written (the README gives the two settings
  `db/migrate.py` needs and `npm ci` before `npm run dev`), and `migrate.py` runs outside this repository, as the
  file manager's does. An open chat loaded its messages again and again, each load marking the chat read and
  telling every member's browser to load it too: it now loads once per change. Its database is published on
  127.0.0.1 only, and its migrations, policy and tests run as the tables' owner (`ms_owner`), not the superuser.
- The messenger example's rules and API: a group's owner could leave it through the API, and the group, without
  an owner, could never be deleted; the owner now stays, and deletes the group instead. Marking a message
  "edited" without editing it is refused. An admin who opened their own group's invite link was told it didn't
  work. A negative `limit`, or a number past bigint's range, answered 500 (now 422 or 400). The chat list counts
  unread messages from their numbers (it read each one: 5.5 s for 100,000). A direct chat whose other person
  left no longer disappears from the list, and a button whose request failed says why.
- Some things only the alphas' release notes said are now in the docs: the SDKs' `not_signed_in(e)` and
  `notSignedIn(e)` (the not-signed-in error, AZ701, and not a refused login), `db.$authz.tableName()` and the
  Python SDK's `verdict(..., named=)`; the `CREATE INDEX CONCURRENTLY` that `rowstile indexes` gives goose and
  dbmate in a migration of their own, a partitioned table's index without it, and the unfinished index a failed
  build leaves, named first; that `rowstile prove --worlds N` tries more worlds than N; what `rowstile sql --as`
  says of a write that changed no row; and a key that two rows hold through a table that inherits (the limits
  page).
- A relative link in a release's notes on GitHub (`[Installing](docs/installing.md)`) led nowhere: the release's
  page reads it from its own address. The notes now link to the file at the release's tag.

## Before the beta

The alphas, from 0.1.0-alpha.1 (2026-10-04) to 0.1.0-alpha.9 (2026-10-19), were for trying rowstile early. The
first was published as rowfence; from 0.1.0-alpha.2 on the project is rowstile, as another product, a proxy for
DuckDB, had the name first. The beta starts afresh: it doesn't upgrade a database an alpha made, and it reads
none of the names from before the rename (see
[what a 0.x release promises](docs/reference/limits.md#what-a-0x-release-promises)). Each alpha's notes are on
its GitHub release:

- [0.1.0-alpha.9](https://github.com/rowstile/rowstile/releases/tag/v0.1.0-alpha.9) (2026-10-19)
- 0.1.0-alpha.8 (2026-10-19): tagged, and never published (its release run stopped before publishing)
- [0.1.0-alpha.7](https://github.com/rowstile/rowstile/releases/tag/v0.1.0-alpha.7) (2026-10-13)
- [0.1.0-alpha.6](https://github.com/rowstile/rowstile/releases/tag/v0.1.0-alpha.6) (2026-10-07)
- [0.1.0-alpha.5](https://github.com/rowstile/rowstile/releases/tag/v0.1.0-alpha.5) (2026-10-06)
- [0.1.0-alpha.4](https://github.com/rowstile/rowstile/releases/tag/v0.1.0-alpha.4) (2026-10-06)
- [0.1.0-alpha.3](https://github.com/rowstile/rowstile/releases/tag/v0.1.0-alpha.3) (2026-10-05)
- [0.1.0-alpha.2](https://github.com/rowstile/rowstile/releases/tag/v0.1.0-alpha.2) (2026-10-04)
- [0.1.0-alpha.1](https://github.com/rowstile/rowstile/releases/tag/v0.1.0-alpha.1) (2026-10-04), published as rowfence

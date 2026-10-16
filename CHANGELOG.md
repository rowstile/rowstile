# Changelog

What changed in each release, newest first. An alpha (`0.1.0-alpha.1`) is for trying a version early: it may
still change before that version is released. Before 1.0, a minor release (0.2.0) may change the policy
language, the `authz.*` functions, the SDKs and the file formats: what to do about it is under **Upgrading**.
Each release upgrades from the one before it. How releases are numbered and made: [RELEASING.md](RELEASING.md).

## Unreleased

### Upgrading

- Apply the policy again (or the next migration) to take the faster lookups below. A closure table built through a
  `(type, id)` pair has a new definition: applying builds it again, once.
- `rowstile review` no longer reads a base branch's policy written in the language before this one (`role`,
  `everyone`, `roles : ... grant`, `and` next to `or` without parentheses): such a base is a base with a mistake,
  and the review reads the head as new. Its `--json` no longer has `base_previous`. Upgrade the policy and merge
  that before upgrading the review's version, or read the first review of the upgrade as new.
- The language no longer names the forms it replaced in its messages: `role app_user` is a line it doesn't read
  (AZ101), `everyone` an ordinary name (write `anyone`), and `roles : ... grant` a list of subjects it refuses
  (AZ103). `everyone` and `grant` may be names now.

### Changed

- The language server underlines the words a mistake is about (`nosuch` in `can view = owner or nosuch`, the
  `(` that isn't closed, the subject a list can't read), where it underlined the whole line; on a line that goes on
  to the next, the words are where they are. `PolicyError.span` says where they are, for code that compiles a
  policy. A line that isn't the form its first word starts (`type folder app.folders`, `can view owner`) has the
  word underlined where it stops being one.
- The parser reads on after a mistake, and the language server shows every mistake it finds in the policy, where
  it showed the first. The lines of a block whose first line is wrong are left out, so each mistake is said once.
  `PolicyError.errors` holds them all; the message, and what `rowstile check` says, are still the first.
- The reference no longer shows `core/compile_policy.py`, which no install carries: previewing a change is
  `rowstile diff new.authz [--users 1,2]`. The script stays the suites' compiler without a database, with three
  modes (`--check`, `--tests`, `--diff`; `rowstile graph` and `rowstile client` replace its `--graph` and
  `--client`), and refuses a flag it doesn't know, two modes at once and `--users` without `--diff` (exit 2), where
  it ignored them or read `--users --diff` as a preview for a user named `--diff`. A test file that isn't UTF-8 is
  named, not the policy.
- Access reviews are for users too: `start_review`, `review_items`, `review_decide` and `close_review` refuse a
  service signed in, "authz.start_review is for users, not services (service 7 is signed in)", AZ715. A service
  the policy let share an object could start a review of it, read and decide its items and close it, and the
  review recorded no one as having started or decided it. Apply the policy again (or the next migration) to take
  it.
- The calls that are for users refuse a service signed in with words that say so, and a code of their own:
  "authz.create_role is for users, not services (service 8 is signed in)", AZ715 (403 in the SDKs). They are the
  custom roles API (`create_role`, `set_role_permissions`, `delete_role`, `roles_of`), access requests
  (`request_access`, `pending_requests`, `decide_request`, `cancel_request`), `break_glass`, a key for oneself
  (`create_api_key` without a principal) and `view_as`. A service was refused most of them already, with a
  message that said it lacked a permission `authz.can` said it held ("you cannot manage roles of team 1"), or
  that nobody was signed in; `pending_requests` gave it an empty list, and `view_as` let a service the policy
  gave `impersonate` view as that user. A service still shares as itself, and a user holding `manage_keys` on
  it makes its keys. Apply the policy again (or the next migration) to take it.
- `rowstile review` reviews a pull request whose base branch's policy has a mistake, where it refused (exit 1),
  so the pull request that fixes the mistake got no review and the review's CI job failed. It says first that
  the base has a mistake, with its line there and its code, and reviews the policy as new, as where the base has
  none; `--json` has it as `base_mistake` (`line`, `message`, `code`).
- `authz.lint()` warns about any permission that makes Postgres write out more than fifty views to plan a check
  of it, with the permission (`note.read`) and its line; applying shows the warning too. It warned for select
  rules alone, so a permission only `authz.list`, `authz.can` or a write rule checks could take tenths of a
  second to plan on every call with nothing said.
- A rule on columns (`update owner_id : share`) has a trigger named after the rule's head
  (`authz_update owner_id`, `authz_update_after parent_id`), no longer numbered in the order the policy writes
  its rules (`authz_update_1`); so are its functions. Postgres fires a table's triggers in the order of their
  names, and the first to refuse an update says why: an update two such rules refuse now shows the words of a
  rule on the row before the change first, then of the one whose columns come first by name, whatever the order
  the rules are written in. They may be the other rule's than before. Apply the policy again (or the next
  migration) to take it.
- Lookups through a type keyed by two columns read rows by each column, so the index on the columns serves them.
  The views compared both columns as one piece of text, which no index serves, and read the whole table: the files
  in the folders a user may edit, the folders of the teams they are in, the rows a `(type, [org_id, id])` pair
  names, and a team's sub-teams where teams nest by a column or a table alone. On `tests/composite.authz`'s tables
  with 50,000 folders and 100,000 files, as the app role, the files a user may view take 7 ms where they took 51
  ms: 18 files read through `files (org_id, folder_id)`, where all 100,000 were.
- A `(type, id)` pair whose id is one column puts the type's own condition beside its `CASE`, with the same
  answers, so an index on `(type, id)` finds the rows of that type and reads no others. On `tests/cross.authz`'s
  tables with 20,000 folders, the folders inside the projects a user files take 0.6 ms where they took 2.9 ms
  (2,000 rows read, where all 20,000 were), and the projects that regions fund 0.3 ms where they took 2.1 ms. The
  id itself is still read through the `CASE`, which no index serves.
- `rowstile indexes` and `authz.lint()` asked for different indexes for a `(type, id)` pair, `(type, id)` and
  `(id)`, and each took only its own as serving the lookup. Both ask for `(type, id)` now, and take an index that
  starts with it, or with the type where the id is one column, or with the ids where they are two. An index on a
  one-column id alone serves no such lookup, and is no longer taken as serving it.
- `rowstile plans` no longer asks "an index missing?" of rowstile's own tables, which it reads whole for someone
  who reaches most rows (an org's admin): no index the app adds changes that.
- Where nothing names them (no `--db`, `database`, `DATABASE_URL` or `PG*` variable), the command connects as
  libpq does: as the system's user (it connected as `postgres`), and on Windows to `localhost` (it tried a Unix
  socket, which Windows doesn't have); elsewhere to the server's socket in `/var/run/postgresql` or `/tmp`,
  whichever has it (it tried only the first, Debian's; macOS's builds use `/tmp`). To connect as `postgres` as
  before, set `PGUSER=postgres` or `user=postgres`.
- When it can't connect, the command says where it tried and what the system said, in words: `can't connect to
  db.example.com port 5433: connection refused`, `can't connect to the socket /var/run/postgresql/.s.PGSQL.5432:
  no such file or directory`, `... : no answer in 10 s (connect_timeout)`. It said only the system's error
  (`can't connect: [Errno 111] Connection refused`), which names neither the host nor the port, though the
  database may come from `rowstile.toml`, `DATABASE_URL`, a `.env` file or the `PG*` variables. So do `dev`,
  Studio (503) and `review --db`.

### Fixed

- The language server underlined the wrong word when a line names it twice: in `can view = owner or
  parent.owner`, where a folder has no `owner`, it underlined the file's own `owner` (#281). A name the compiler
  looks up keeps where it was written: in a permission, a relation's subjects, a scope's items, an invariant's
  type and the custom roles' line. A typo after a dot (`parent.ownr`) is said as the name it is, where it was said
  as the relation it then leaves unused.
- A condition ends at the brace that closes it, not at the line's last `}`: `shared if {a} and {b}` was read as
  the one condition `a} and {b`, which Postgres refused only when applying, and two lines run together (`given a
  = {...} given b = {...}`) as one statement. The same for a type's and a link table's `where`, a caveat, and a
  test's `given` and `as`. Such a line is refused now (AZ101, AZ103, AZ106).
- A condition reads quotes as SQL does: a `}` or `--` inside `"a name"`, `$$text$$` or `E'it\'s'` is part of
  the condition, where it closed the condition or began a comment, and a quote may go on to the next line. Outside
  conditions, a quote that doesn't close on its line is an apostrophe: `test Bob's test -- note` names the test
  "Bob's test", where the comment was kept in its name. `rowstile fmt` reads quotes, braces and comments the same
  way as the parser.
- A scope defined twice is refused (AZ109), as a type or a caveat is: the second one replaced the first.
- A policy file that starts with a byte order mark and includes another, read from disk, found it: the include
  on its first line was missed, and the message said to pass the file in the `files` argument.
- `test "name` without its closing quote is refused (AZ106), where the quote was taken as part of the name.
- `rowstile review` flagged a `where` added to a link table's relation, or one that holds for fewer rows
  (`{active}` made `{active and not banned}`), as a permission that allows more than before. It allows less, and
  is no longer flagged.
- `this.` in a condition named the subquery's table when the subquery's alias was u, w, o, r or share (or c, s
  or x), or, in a rule, when the subquery read the rule's own table without an alias: `{not exists
  (select 1 from app.bans u where u.user_id = this.id)}` in the user type's `where` compared each ban with
  itself. `this.` now names the condition's row wherever it is placed. Names that start with `authz__` are
  rowstile's own, and a condition that writes one is refused (AZ113). Only such conditions are written anew:
  where a policy has one, apply it again (or make the next migration) to take it.
- `rowstile fmt` left a line that starts with `or` (or `and`, `where`, `if`, `grant`) at the start of its line,
  after a blank line it added, when it wasn't indented. The policy reads it as the line before it continued, and
  fmt now lays it out so: under the expression it continues, as it does an indented one.
- Studio's "Make a test" (`/api/test`) wrote a test for a permission the type doesn't have, or for a relation,
  which `rowstile test` then refused. It now refuses them as `why` does: 400, "no permission folder.nope in the
  policy", AZ707. A type the policy doesn't have is answered the same way: 400 and AZ707, where it was 404.
- Studio read a change's body whatever its size, before deciding anything, and waited as long as the client kept
  the connection open for a body that never came. A body is now 64 KB at most: a longer one is refused before it
  is read (413), and so is a missing or wrong `Content-Length` (411, 400). One that hasn't come whole after 10
  seconds is given up on (408). A read-only Studio refuses a change (403) before reading its body, and a connection
  that sends nothing for 10 seconds is closed.
- After `rowstile dev` or `rowstile studio` started again, a page still open from the run before was answered only
  "the token from the URL rowstile printed". It now says that Studio was started again since the page was opened,
  each start making a new token, and to open the address rowstile printed last. The page forgets that token, so
  reloading it asks for the new address.
- A list or a read could take seconds on a few rows, on some policies with inheritance: where Postgres put a
  permission's starting points on the inner side of a nested loop, it worked them out again for each row (on one
  random policy, a list of seven rows took 1.3 s and made 10,768 calls where 76 do; now 10 ms). They are now
  worked out once where they are read. Apply the policy again (or the next migration) to take it.
- For goose and dbmate, the `CREATE INDEX CONCURRENTLY` that `rowstile indexes` gave failed inside the transaction
  those tools run each migration in. It now says to put it in a migration of its own that starts with
  `-- +goose NO TRANSACTION` or `-- migrate:up transaction:false`.
- A `CREATE INDEX CONCURRENTLY` that fails leaves an unfinished index under the name `rowstile indexes` gives, so
  running its line again failed with "already exists". `rowstile indexes` now names that index first, to drop.
- `rowstile review` said "Meaning unchanged" for some changes that do change access: a condition added to a long
  `and` (or taken from it), or one that must say one thing on a row and another on the row it inherits from. Its
  small worlds were drawn at random, and such a world came up one time in hundreds. Now, beside the drawn worlds,
  it lists the worlds of up to 3 rows of each type, the fewest links first, each row with every answer its
  conditions can give, and tries every one with no link or one link, then more up to 3,000 worlds. "Meaning
  unchanged" says how far it got: "200 small worlds and 3,000 listed: every one of up to 3 rows of each type with
  at most 2 links", and where columns read together have more than 4,096 combinations of values, that it tried the
  first 4,096 only. A review of a typical policy takes 1 to 4 seconds more.
- `rowstile review` could show a difference for a rewrite that changes nothing. In the small worlds where every
  condition holds, or none does, it chose a row's column values for each policy's own conditions, so where the
  rewrite read a column beside another (`{not b1} or ({b1 and b2} and nobody)` for `{not b1}`) the two
  policies were compared on different rows. Both now read the same values.
- The command lost its connection right after signing in, before its first statement, with a traceback. It
  now says it lost the database (exit 2), as it does anywhere later.
- A share could outlive the row it was on or to, where a row was deleted, given a new id or emptied with
  `TRUNCATE` by a transaction in REPEATABLE READ or SERIALIZABLE that had taken its snapshot before someone
  else's share of that row was committed: the delete went through and left the share, and a row given that id
  later had it too. It affected apps whose deletes or changes of id run in those levels, beside sharing at any level
  (not both in SERIALIZABLE). Such a delete now fails with a serialization error (40001), to retry, and the
  share goes with the row. `authz.break_glass` locked nothing, so a folder deleted while someone broke the glass
  on it kept that share even in READ COMMITTED; it now locks the row and the user as `authz.share` does, and
  waits for the delete. A share now takes a short lock of its own on the object and the subject, so two shares
  of one object at once wait for each other, and in REPEATABLE READ the second fails with 40001.
- `authz.explain` (and what calls it: refused writes' reasons, `authz.explain_rule`, `rowstile why`, Studio and
  the SDKs' explain helpers) said a user held a relation by a share, then described the oldest share of that
  relation on the object: often another user's, or another link than the one presented. Anyone a share was given
  to saw who had made someone else's share there, until when, and its caveat, and might read another person's end
  date as their own. It now describes the share that gives them the relation: their own, the link they presented,
  or the one to every signed-in user. Apply the policy again (or the next migration) to take it.
- A principal's API keys outlived its row: a user or a service deleted, or given a new id, kept its keys, and a
  row that later had that id signed in with them. It affected apps that delete users or services with keys, or
  change their ids, and reuse ids. The keys now go with the row, with a line each in the audit trail (deleted,
  as the row's shares are, when its id changes or its table is emptied), and applying the policy deletes the keys
  left by rows deleted before. A key made while its principal is deleted waits for the delete and is refused; a
  delete in REPEATABLE READ or SERIALIZABLE that can't see a key made since fails with a serialization error
  (40001), to retry. The same held for a pending access request: one whose requester or object was deleted, or
  given a new id, stayed pending, so a later user with that id saw it as theirs, and approving it shared the
  object, or a later object with that id, with them. A pending request is now cancelled with its requester's or
  its object's row, and applying the policy cancels those of requesters deleted before; decided requests stay as
  they were.
- A URL's `ssl=true` now requires TLS, as `psql` reads it (`sslmode=require`). The command left it out as an
  option meant for another tool, so the connection used `sslmode=prefer`, which goes on without TLS when the
  server, or anything between, says it has none. Any other value of `ssl` (`ssl=false`, `ssl=1`) is refused, as
  libpq refuses it.
- `rowstile prove` and the review read a decimal in a condition (`{price >= 1.5}`) as a float, so
  `1.00000000000000001` was 1: prove gave counterexamples a `numeric` column can't have, and the review said
  "Meaning unchanged" when `{price >= 1}` became `{price >= 1.00000000000000001}`. They now read numbers exactly,
  as `numeric` does, and only those a `numeric`, a `double precision` and a `real` column all hold as written,
  with the values the worlds draw around them (`0.5`, `0.25`, `100`); any other (`0.1`, which a `real` column
  holds as 0.100000001; `1.00000000000000001`; `16777216` and above, whole numbers a `real` column rounds near)
  is left to the database, as any condition they can't read.
- `rowstile prove` and the review didn't read quoted column names in conditions (`{"done"}`, `{not "archived"}`,
  `{"order" = 2}`): such a condition was one they couldn't read, so `{"done"}` and `{not "done"}` could both hold
  on one row, and quoting a column was a change of meaning. They now read them as Postgres does, case kept.
- `rowstile migrate` and `migrate --check`, refusing a lock file a newer rowstile wrote (AZ616), left out the
  hint `apply` and `push` give: "upgrade the rowstile command; to go back to this version on purpose, add
  --downgrade". They now give it too.
- `rowstile review --db` stopped at a test file of the pull request with a mistake (a line that doesn't parse, a
  check naming a permission the type doesn't have): it printed that mistake alone and exited 1, with no review and
  no comment to post. It now names the file under Tests with its mistake, runs the other tests, and goes on (exit
  0), as without `--db`. Without `--db`, a test file that parses but that `rowstile test` would refuse with the
  pull request's policy (a permission it doesn't have, a test another file names too) went unnoticed, and its
  checks were compared: it is now named the same way.
- A share of a relation that inheritance follows, with an expiry, a start time or a caveat, was refused with the
  code at the end of the message ("... cannot expire, start later or have a caveat [AZ605]") and no HINT, so an
  app that shows the database's words showed the code. The code is now in the HINT, `rowstile help AZ605`, as for
  every other error an app can meet; the SDKs read it there. Apply the policy again (or the next migration) to
  take it.
- For a plain `update` rule (no `update after`), what `authz.explain_rule` said "after the change", and the DETAIL
  of an update the rule refused on the row after the change, explained a permission the changed row lacks with
  `authz.explain` on the row as stored: a "yes" under a "no" ("no   edit", then "yes  user 2 holds edit on folder
  4"). The row after the change now gets no such explanation, as for inserts and `update after` rules: only the
  rule's items, yes or no. Apply the policy again (or the next migration) to take it.
- A `+` in a `postgresql://` URL's query (`?dbname=`, `?password=`, `?options=`) is a `+`, as libpq reads it:
  the command read it as a space, so a password with a `+` was changed before it was sent, and it didn't connect
  where `psql` does with the same URL.
- The command prints the warnings the server sends as a session starts, as `psql` does: a database's collation
  version that doesn't match the system's (after an upgrade of the system, which can leave indexes wrong), or a
  setting of the database's or the role's the server can't take. It dropped them; it printed only those sent
  once the session had started. `rowstile dev` shows them as it shows a warning.
- When the server ends the command's session in the middle of a run (an administrator's `pg_terminate_backend`,
  a server shutting down), `apply`, `push`, `reapply`, `dev` and the others say why, in the server's words:
  `lost the database: terminating connection due to administrator command`. They said `lost the database:
  [Errno 32] Broken pipe` when the session ended between two statements on a local socket, or while one waited
  for a lock: the command undid its savepoint, or tried the policy's conditions alone, on the closed
  connection, and that error took the place of the server's. And `rowstile review --db` says it lost the
  database, where a session ended as it began gave a traceback.
- Ctrl-C while `rowstile apply` or `push` ran a statement of the policy (waiting for a lock another session held,
  say) was heeded only once that statement ended: a wait for a lock went on to the lock timeout, and the command
  reported the timeout. It stops at once now, ends the statement on the server and keeps nothing, as `sql` does.
- `rowstile mcp` ignored `notifications/cancelled`: a call the agent cancelled ran to its end (a `push` changed the
  database all the same) and was answered, and a `ping` sent meanwhile waited for it. Each call now runs beside
  the messages after it: a ping is answered at once, and a cancelled call's command is stopped as Ctrl-C stops it
  (a push keeps nothing) and gets no answer, as MCP asks.
- The commands `rowstile mcp` ran for its calls kept running after the server was stopped (SIGTERM, as an
  agent's client stops it once it has closed the server's input): a `push` waiting for a lock went on to the
  lock timeout, a long `prove` to its end. The server now stops them first, as it stops a cancelled call, waits
  for them (10 seconds, then they are killed), and ends after them.
- `rowstile lsp` stopped at start (exit 2) on a mistake in `rowstile.toml` (a setting it doesn't know, a TOML
  mistake): the editor had no language server at all, and the mistake was only in the server's log. It starts
  now, shows the mistake on `rowstile.toml` (its line) and in a message, checks the policy without the file's
  settings, and reads the file again when it changes, so a fix is taken at once.
- `rowstile lsp` never tried again a database it couldn't reach at the first completion that needed it (not
  started yet, say): no table or column names until the editor restarted the server. It tries again some seconds
  later (5, then 10, 20, up to a minute between tries), and at once when `rowstile.toml` changes.

## 0.1.0 (alpha)

**rowfence is now rowstile**, and 0.1.0-alpha.2 is its first release under the new name (0.1.0-alpha.1 was
published as rowfence, and those packages stay at that version). Another product, a proxy for DuckDB, was
already called Rowfence, so the project takes a name of its own. The command is `rowstile`, the packages are
`rowstile` on PyPI and npm and `@rowstile/*`, the image is `ghcr.io/rowstile/rowstile`, the docs are at
https://rowstile.dev, and the repository is github.com/rowstile/rowstile. The policy language, the `authz`
schema, the `authz.*` functions, `.authz` files and the AZ error codes keep their names; **Upgrading** below
says what to change.

The first release, as an alpha: for trying rowstile early. Anything in it may still change before 0.1.0
([what a 0.x release promises](docs/reference/limits.md#what-a-0x-release-promises)). It holds:

- **The policy language** (`.authz`): types read from the app's tables, relations from their columns and link
  tables, permissions built with `and`, `or` and `not` and inherited down trees, rules for each table and
  command, column rules and masked columns, conditions in SQL, custom roles, shares that expire or carry
  conditions, scopes, invariants and tests.
- **The `rowstile` command**: compiles a policy into views, trigger-maintained inheritance tables, row-level
  security policies and `authz.*` functions, applied as the tables' owner, with no extension and no superuser.
  Each change to the policy is a migration for Alembic, Prisma, Drizzle Kit, plain SQL, goose, dbmate or
  Flyway. Beside it: `init`, `dev`, `test` (with coverage), `prove`, `review`, `diff`, `why`, `fmt`, `lint`,
  `indexes`, `plans`, `bench`, `graph`, the generated clients, Studio, the language server and an MCP server
  for coding agents.
- **What apps call** (`authz.*`): signing in (`act_as`, API keys, JWTs), checks and lists (`can`, `list`,
  `perms_of`), sharing, who has access and why, the audit trail and change feed, access requests, break-glass,
  access reviews and view-as.
- **The SDKs**: Python (FastAPI, SQLAlchemy, psycopg, asyncpg, Alembic, pytest) and TypeScript (pg,
  postgres.js, Prisma, Drizzle, Next.js, React, Vitest).
- **The review for pull requests**: a GitHub action and a GitLab CI template that comment what a policy change
  does to access.
- **Editors**: VS Code, Zed, and a Tree-sitter grammar for Helix and Neovim.

PostgreSQL 16, 17 and 18. Installed with npm (the command with its own Python), pip or the Docker image:
[Installing](docs/installing.md).

What changed since 0.1.0-alpha.6:

### Upgrading

- The next `rowstile migrate` (or `apply`) brings the errors' new SQLSTATEs and codes: a migration with no
  change to the policy. Code that read an SQLSTATE these errors had before (23503 for a share with someone who
  doesn't exist, 42501 for "sign in first") reads the code in the HINT instead (`rowstile help AZ714`). Until
  then, through `@rowstile/prisma`, a share with someone who doesn't exist answers 500.

### Added

- Two starters, as template repositories: [FastAPI, SQLAlchemy and
  Alembic](https://github.com/rowstile/starter-fastapi) and [Next.js and
  Prisma](https://github.com/rowstile/starter-nextjs-prisma). Each is a small app where documents are shared
  with people and teams and no route checks a permission, with its policy, its tests, the review in CI, and
  an open pull request that shows the review's comment. The stack pages link them.
- The command reads `.env.local` and `.env` beside `rowstile.toml` (in the current folder while there is
  none) for where the database is: `DATABASE_URL`, the `PG*` variables, and the variable `database =
  "env:NAME"` names. The environment comes first, then `.env.local`, then `.env`; `rowstile dev` says when the
  database came from a file, and so does a connection that fails. Nothing else in those files is read, a
  file that is a link out of the folder isn't read, and with `--db` neither is. A Next.js or Prisma app
  keeps its URLs there: `npx rowstile init` and `npx rowstile dev` failed for want of them. (#96)
- The command reads `PGOPTIONS`, as psql does, where the connection string gives no options: a session's
  settings (`-c search_path=app`) applied with the policy were psql's alone. From the environment or `.env`, like
  the other `PG*` variables.
- `rowstile <command> --help` prints that command's lines of the usage and where the database comes from,
  where it printed the whole usage. `rowstile init --help` says which schema `init` reads when none is
  named: `public`.

### Changed

- Signing in (`authz.act_as`, `authz.login_key`, `authz.login_jwt`, `authz.view_as`) turns JIT off until the
  transaction ends, so `ALTER ROLE app_user SET jit = off` is no longer needed, and `authz.lint()` and
  `authz.connection_check()` no longer report JIT. The rules' lookups are estimated once per row, so a read of
  a few thousand rows through them looked costly enough to compile: with JIT on, counting 10,000 folders took
  1.06 s instead of 23 ms. The setting of the role reached only that role's own logins, not its members. An app
  that wants JIT back for one transaction runs `SET LOCAL jit = on` after signing in.
- Applying and migrations analyze the tables the policy reads, and rowstile's own, that were never analyzed:
  Postgres planned a table of a few rows as thousands, and JIT compiled reads of it (160 ms for 17 rows).
- Each run of the command starts faster: it imports only what that command uses. `rowstile check` and `rowstile
  test` take about 35 ms less CPU of about 180, and `rowstile fmt`, `can`, `lint` and `--version` about 50 ms
  less of about 160: a hook or a CI step that runs the command many times gains the most.
- `rowstile review` stops when git can't read a file it needs at the base: the policy, a file it includes, the
  lock file or a test file (a partial clone that can't fetch it, a repository missing objects). It says "git
  can't read db/policy.authz at main", why, and how to fetch the base's history, and exits 2. It went on as if
  the file weren't there: the policy reviewed as new, a file it includes called a mistake of the base's, Deploy
  worked out as if the base had no lock file, the base's tests left out. A file the base doesn't have (a new
  policy, a test file added since) is reviewed as before.
- `rowstile sql` writes values as Postgres writes them, as psql shows them: `t`, `{x,"y z",NULL}` and
  `{"k": 1}`, where it wrote Python's `True`, `['x', 'y z', None]` and `{'k': 1}` (which isn't JSON).
- `rowstile lsp --db` is refused: the language server reads the database `rowstile.toml` names, and ignored
  `--db` without saying so.
- `authz.unshare` says what it needs: "you cannot unshare editor on folder 3 (needs manage_editors)", where
  it said "you cannot share folder 3", also to someone who may share folder 3. The same words for an object
  the caller can't see and one that doesn't exist, as before; the code (42501) and the hint (AZ705) are the
  same.
- `rowstile prove` finds a counterexample that needs several conditions at once in fewer worlds: at each
  size it tries, besides worlds drawn row by row, worlds where every condition holds on every row or on none,
  as the review's refactor check does. One that needs `{b1 and b2}` on one object and `{b1}` on another was
  found at the 191st world, and missed with `--worlds 200`; it is found at the 12th. Over 1,200 random
  policies, of 952 invariants that can be broken, it missed 1 with 400 worlds where it missed 4, and 4 with
  200 where it missed 12, for about a sixth more time. The worlds it tries include those, so `--worlds 80`
  counts more than 80.
- A migration run on a database that already holds what it brings says so: "this database already holds
  what this migration brings (it ran here before, or rowstile dev or push took the database there): don't
  run it, tell your migration tool it is applied [AZ607]", with the Prisma and the Alembic command in the
  hint. That is what a development database `rowstile dev` pushed to answers to `prisma migrate deploy` or
  `alembic upgrade head`; it said "this migration changes the policy the migration before it left".
  Migrations written before keep their words.
- A refusal's `table`, `command` and `code` say the same thing whichever rule refused (the 403's fields:
  <https://rowstile.dev/problems/refused>). An update or delete that `expect` explains names the table as
  the policy does, with its schema, as a refused insert always did: `public.Note` for a Prisma model `Note`,
  where it said `Note` (so does the 404 for a hidden row: `public.Note 2 not found`). A column's rule gives
  the table and `update` through Prisma too, which drops the error's fields. And `code` is the database's
  own: AZ705 for a share by someone who may not share, where every refusal said AZ709. In the TypeScript
  SDK `db.$authz.tableName("Note")` gives the policy's name for a table; in the Python SDK `answer()` returns
  that name as a third value, and `verdict()` takes it (`named`).
- `authz.lint()` names a table the policy reads for a relation when the app role may read every row of it
  (a note, like the one for a type's table without rules): who is in which team is readable.
- AZ602, a key of another type, says which: "public.User.id is integer, not bigint: write its type after
  the key, (id integer)". It said "e.g. (id uuid)".
- `rowstile init` drafts a user's own row as the reference says to write it, a relation: `self : user = id`
  and `can edit = self`, where it wrote `{id = authz.uid()}`. And a link table's relation leaves the type's
  name out however the table is spelled: `TeamMember` gives `member`, as `team_members` does.
- While only alphas are published, each release moves npm's `latest` to the alpha it publishes: a plain
  `npm i rowstile` gets the newest, and a package's page on npmjs.com shows it. `next` names it too, as
  before. From the first final release on, `latest` is a release's only.
- Each error the runtime raises comes with one SQLSTATE, the one its code's page names, and the SDKs answer
  each code as its page says; every page now names both (`rowstile help AZ713`). What changes for apps:
  - A call that needs someone signed in, made by a visitor who isn't (`authz.request_access`,
    `authz.create_api_key` for oneself), has a code of its own, AZ714, "sign in first", and answers 401
    (`https://rowstile.dev/problems/not-signed-in`). It was AZ701, and answered 403 as if a rule had refused
    it. A login with an API key or a token the database refuses (AZ703) answers 401 too: `rowstile.fastapi`
    raised `NotSignedIn`, a 500 saying nobody had signed in.
  - A move that would put an object inside itself (AZ713) answers 409
    (`https://rowstile.dev/problems/conflict`), where it answered 500.
  - `authz.create_api_key` for a type whose keys the policy lets nobody manage (AZ707) is the app's mistake,
    a 500, as AZ707's other errors are: it said 42501, and answered 403 as a refusal.
  - A share that the relation's `shared if` doesn't allow is AZ705, a refusal (403, as before), where its
    code said AZ706.
  - The SQLSTATEs that differed: AZ708 is P0001 (a share with someone who doesn't exist said 23503,
    revoking an API key that isn't yours 42501), AZ710 is 22023 (a missing reason, approve or deny, a
    duration said P0001), AZ707 is P0001 (`authz.act_as` with a type that doesn't sign in said 22023,
    `authz.explain_rule` for a table without rules 42P01), and JWT login that isn't set up (AZ703) is 28000.
  - `not_signed_in(e)` and `notSignedIn(e)` are true for strict sign-in's error (AZ701) only: a login refused
    (AZ703) and settings changed by hand (AZ702) have its SQLSTATE, 28000, but are no such thing.

### Fixed

- `rowstile diff`, and with it the Access part of `rowstile review`, could fail with "permission denied for schema
  pg_toast" where the tables' owner is no superuser: on a database many diffs had run on (each one leaves dead
  rows in the catalog, and Postgres then reads it another way round), the seventeenth in a row in one try. It
  finds each policy's table by its oid now, never by a name read back as a table.
- A write refused by an `after` rule (`update after : edit`, `update owner_id after : ...`) gave as its reasons
  the permission on the row as stored, not as changed: giving your file away was refused with "no edit", then
  "yes, user 3 holds edit on file 90: owner_id is you". Its reasons now stop at the permission the row as changed
  lacks (what it points at, such as a folder, is still explained), and so does `authz.explain_rule`'s "after the
  change". The next `rowstile migrate` (or `apply`) brings it.
- `rowstile why`, Studio's how-to-grant and the MCP server's `why` turn JIT off for their own transaction. On a
  server with JIT on, Postgres could spend most of a second compiling each count of what someone holds, though
  the table held a few rows: Studio's own tests ran in 47 seconds instead of 129.
- The SDKs answer a call the database says names something that isn't there (AZ708) with 404, and one it says
  lacks an argument or has a wrong one (AZ710) with 400, as those codes' pages say, each with a problem body
  in the database's words: `rowstile.fastapi`, and `route()`, `action()`, `authzRoutes()` and `problemOf(e)` in
  `@rowstile/next` and `@rowstile/client`. A negative page size or a page cursor that isn't an id answered 500;
  a share with someone who doesn't exist answered 500 through `authzRoutes()`'s share route and `route()`;
  revoking an API key that isn't yours (or isn't there) answered 403 as if a rule had refused it. The 404's
  body is `https://rowstile.dev/problems/not-found`, with `code: "AZ708"`; the 400's is
  `https://rowstile.dev/problems/bad-argument`. (#164)
- `@rowstile/prisma`: a write refused inside `$transaction(async (tx) => ...)`, or a `findUniqueOrThrow` that
  found no row there, is explained through the transaction. The question went outside it, and on a pool of one
  connection waited for the one the transaction held, until Prisma's transaction timeout (5 s). (#165)
- `@rowstile/prisma` named the table of a model with no `@@map` in a named schema (`@@schema("app")`) without
  its schema in a refusal read back (`feedback`, where the policy says `app.feedback`). (#166)
- After the app dropped a column that only a signing-in type's `where` (or a `shared ... if`) reads, every query
  of the app failed, yet `rowstile apply` said the policy was unchanged and `rowstile push` (and `rowstile dev`)
  pushed another change without a word: only `apply --force` refused it. Apply and push now read those
  conditions again each time, and refuse one that no longer runs with its line, as the first apply did
  (AZ613).
- `rowstile indexes`, `rowstile dev` and `authz.lint()` didn't look at the index on a type's own key, by which
  every check on one object (`authz.can`, a write rule) finds its row: on a table with no primary key there, each
  such check scanned the table, and nothing said so. They name it now, like any other lookup, with the index to
  add. A primary key, a unique index or any index whose first columns are the key's (in any order) serves it.
- `rowstile review --db` stopped with a traceback when the server ended its session in the middle of the review
  (a restart, or `pg_terminate_backend`): it says it lost the database, exit 2, as the other commands do. Its
  messages name the policy as you do (`db/policy.authz`), not by its full path; and `review`, `test` and `dev`
  name a test file they can't read the same way.
- `rowstile review` said "the policy at the base has a mistake" of a new policy whose file name has a `[`, `*` or
  `?` in it: git read the name as a pattern, found nothing, and gave no error. It is reviewed as new, as any
  policy the base doesn't have.
- `rowstile review` said "1 check removed" of a test file the `tests` glob doesn't find, left as it was by the
  pull request: one in a folder below the glob's (`db/tests/old/x.authz` for `db/tests/*.authz`), or one whose
  name starts with a dot. The base's test files were found another way than the pull request's, a `*` matching
  across folders; they are found the same way now.
- `rowstile dev` with a connection string it can't read (`--db colour=blue`) stopped with a traceback: it says
  it can't connect, exit 2, as the other commands do. `--port` and `--studio-port` took a number above 65535,
  which stopped Studio with a traceback: it is refused, exit 2. And `rowstile why --as anyone` exited 1, where
  `why`'s other usage mistakes exit 2: it exits 2.
- A file the command couldn't write was said as a lost database (`rowstile snapshot --out` naming a folder,
  `rowstile client` writing to a folder, `rowstile init` where `db` is a file), or stopped the command with a
  traceback (`rowstile migrate`, and `rowstile client` from the policy file; in `rowstile dev`, the migration
  written once you stop editing, which ended the loop). It names the file and why: `out: Is a directory`, exit
  2; `rowstile dev` says so and goes on. `rowstile snapshot` makes the folder it writes in, as `migrate` and
  `client` do: `[review] snapshot = "review/access.snapshot"` said the database was lost.
- `rowstile dev` kept a connection the server had ended in the middle of a push (a restart, or
  `pg_terminate_backend`): it gave the server's message and "nothing applied", the next save failed with "lost
  the database: [Errno 9] Bad file descriptor", and only the one after worked. It says it lost the database,
  and the next save connects again. A policy with an expression nested too deep to read stopped `rowstile dev`
  with a traceback, the loop with it; it is said as `rowstile check` says it. And who loses rows was said as
  "3 user(s) lose rows readable on 3 app.filess": it is "rows readable in app.files (3 rows)", as the review
  says it.
- `rowstile dev` lost the database as it looked for the lookups no index serves, once its first pass was
  through: a connection closed without a word from the server stopped it with a traceback, and a session the
  server ended was kept, so the next save said "lost the database: [Errno 9] Bad file descriptor" and only the
  one after worked. It says "lost the database", goes on watching, and the next save connects again.
- Studio answered 500 "[Errno 32] Broken pipe", with a traceback where it runs, when the server ended its
  session while a request waited (a restart, or `pg_terminate_backend`), and 500 when the connection closed or
  was reset without a word from the server. It answers 503 "lost the database: terminating connection due to
  administrator command" (the server's words), or "lost the database: the server closed the connection", as
  the command says it, with no traceback; the next request connects again.
- `rowstile review --db` on a database whose owner may not switch to the app role said so without the `GRANT`
  to run, which `rowstile test` gives: it gives it now.
- `rowstile migrate --check` listed twenty changes and stopped there, as if they were all: it says how many
  more, as `rowstile migrate` does.
- The language server stopped, and the editor said it had crashed, when a test file was opened while
  `rowstile.toml`'s `policy` named a file outside its folder (which the command refuses). The test file shows
  why on its first line now. A `policy` that names a file that isn't there is shown the same way, where it was a
  warning that the checker failed.
- The language server's completion inside `{ }` offered each column by its bare name: a column with capitals, as
  Prisma names them (`parentId`), or one named with a word SQL keeps (`user`, `order`) made a condition that
  applying refused, or, for `user`, one about the session's role. It offers them as SQL names them now, quoted
  where they must be (`"parentId"`). In a link table's `where { }` it offered the type's columns, where the row
  is the link table's, and in `shared if { }` too, where the row is the share being made (`object_id`,
  `subject_type`, `subject_id`, `subject_relation`). And it offered tables a policy can't name (a space in the
  name).
- The language server offered the words a line begins with (`type`, `rules`, `include`, ...) inside comments and
  after a line's first word, and an editor asks at each space typed: each word of a comment brought the list up.
  Nothing is offered there now, and after `type x =` and `rules` only the tables.
- When the database in `rowstile.toml` can't be read (it is down, it refuses the connection, the setting is
  wrong), the language server says why in its log, once. It went on without the tables' names and said nothing.
- `rowstile test` passed a `refused` check it never ran when the policy has no rules and the tables' owner may
  not switch to the app role (as an owner that made the role on PostgreSQL 16 or later): the refused switch
  read as the statement refused. It says what to grant first now (AZ618), as it did for a policy with rules;
  so does `test --coverage`.
- A condition Postgres refuses was named with another condition's line when that one's text is part of it:
  `{inherit =}` was reported as `{inherit}`, two lines up, and so was `{confidential or inherit}` on a table
  without that column. `rowstile apply`, `push` and `dev` name the one that fails now. A syntax error Postgres
  finds after the condition, as with a parenthesis left open in a rule, is named too: it was reported in
  Postgres's words alone (AZ613).
- `rowstile diff` names a condition Postgres refuses with its line, as `apply` does (AZ613): it gave Postgres's
  words alone. `rowstile review --db` stopped with a traceback on a pull request with such a condition, or
  one that fails on a row of the review data (`{name::int > 0}`); Access says why now, and the review goes on.
- `rowstile remove` gave back the table-wide SELECT a mask had replaced, and left the SELECT on the table's
  other columns that the mask gave instead. It takes those back too: the table's privileges are as they were
  before the policy.
- On Windows, Studio (`rowstile studio`, and the one `rowstile dev` starts) holds its port on 127.0.0.1 alone,
  as it does on Linux. On a port another program listens on, it says it didn't start and how to choose another
  port, where Windows let it start beside the other program; and no other program can bind its port while it
  runs.
  Security advisory [GHSA-9gh9-rmmx-grpv](https://github.com/rowstile/rowstile/security/advisories/GHSA-9gh9-rmmx-grpv).
- Studio's URL names 127.0.0.1, where it listens: `http://127.0.0.1:4983/?token=...`, where it said
  `localhost`. To a browser that is another address, so the page's remembered "view as" choice starts fresh
  once. A page opened at `localhost` by hand is still answered.
  Security advisory [GHSA-9gh9-rmmx-grpv](https://github.com/rowstile/rowstile/security/advisories/GHSA-9gh9-rmmx-grpv).
- `rowstile studio` printed a Python traceback when it couldn't start: on a database it can't reach (a server
  that isn't running, a database that isn't there), connected as a role that can't read rowstile's tables (an
  app's own `DATABASE_URL`, say), and on a port another program listens on. It says "can't connect: ..." as the
  other commands do (exit 2), the database's words ("rowstile studio: permission denied for schema authz", exit
  1), and "Studio didn't start (...): rowstile studio --port N for another port" (exit 2). A page whose
  database stops answering while Studio runs is told "can't connect" (503), where Studio printed a traceback at
  each request.
- The test Studio writes from "Ann should see this" didn't run for an object, or someone, whose id isn't one
  word: a key with text in it that holds a space or an apostrophe. The test's lines now quote such an id, as a
  test reads it. Its copy of a row wrote an array column as JSON, which Postgres refuses ("malformed array
  literal"), and a number with a fraction as a float, losing digits: each is now written as the column holds
  it. The copy also left out every column with a default, and so took the default where the row holds another
  value: the copy of a folder that doesn't inherit inherited, a confidential file's wasn't confidential, a
  locked note's wasn't locked. It copies them now, and leaves to the table only what it fills itself (an
  identity, a sequence's next value, a generated column). And on tables named with capitals, as Prisma names
  them, it failed: `relation "public.user" does not exist`.
- Studio says what the other commands say. With the policy taken out while it runs (`rowstile remove`), the
  tab of shares and requests said "function authz.act_as(unknown, unknown) does not exist", and why and the
  access diff said "no policy is applied [AZ609]" without how to apply one: each now says "no policy is applied
  [AZ609] (rowstile apply db/policy.authz)". Through an app role its connection may not take (an owner on
  managed Postgres that made the role but wasn't given it), the tables said "GRANT app_user TO the role Studio
  connects as": they now say what `rowstile test` and `sql --as` say, with the role to grant to, who may run
  the grant, and the code (AZ618).
- The audit trail's guard holds in every replication role. Its triggers were ordinary ones, which
  `session_replication_role = replica` turns off, so a superuser who set it could change or delete entries
  without the DDL the reference says that takes. They fire whatever the session sets now (`ENABLE ALWAYS`),
  and `authz.trim_audit` turns the guard back on that way; a logical replication subscription that copies the
  trail still applies the trims made where it is published. `authz.lint()` warns when the guard isn't on in
  every replication role (a data-only `pg_restore --disable-triggers` leaves it on in ordinary sessions only),
  and says that `rowstile reapply` puts it back. **Upgrading**: apply the policy again (or the next migration).
  Security advisory [GHSA-27xr-5hqr-j592](https://github.com/rowstile/rowstile/security/advisories/GHSA-27xr-5hqr-j592).
- An invariant wasn't checked where a permission or a relation of its type was named `never_1` (`never_2` for
  the second invariant, and so on): `authz.check_invariants()` and the policy's tests said it held. Where only a
  mask named such a relation, applying failed instead. Each invariant has a view of its own now. **Upgrading**:
  apply the policy again (or the next migration).
- `authz.explain_rule` for an update, on a table with an `update after` rule for the whole row, gave the
  `update` rule after the change too, which Postgres doesn't check there: it could say "no" of an update that
  goes through. After the change it gives the `update after` rule alone. **Upgrading**: apply the policy again
  (or the next migration).
- `rowstile review` said "nothing flagged" for a column rule that allows more than before when its line was
  written `update owner_id before : ...` (another way to say `update owner_id : ...`) or with its columns as
  `a,b`: it named the rule by its text, and looked for what allows more under the name the rule is read with.
  It names a rule as it reads it now, and flags what it lets through.
- `rowstile review --db` stopped with a traceback when the pull request's policy reads a column the review
  database doesn't have yet (one the pull request's own migration of the app adds). Access now says it isn't
  computed, and why; the review goes on, and says the tests didn't run and the migration fails on the review
  database.
- `rowstile review` made up differences next to a condition it can't read (a subquery, a function) that the
  pull request reworded. The small worlds hold such a condition as rows of its own, drawn by its text, so a
  permission that reads it, or one that only reordered its `or` around it, was said to allow more than before,
  with an example, or named as the difference that makes the change no refactor. The worlds now take that
  condition as the base wrote it and compare the rest; the review still says it can't compare the condition.
  A rule written `after` is named so in a difference, not `update check`.
- `rowstile review` said "Meaning unchanged" for a change inside a condition's `$$...$$` string (`{status =
  $$a  b$$}`): it read the spaces there as layout. Text between `$$` is compared as written, as between quotes.
- `rowstile review` called a change between `signed_in`, `anyone` and `nobody` a condition it can't read, in SQL
  the policy never wrote (`{authz.uid() IS NOT NULL}` -> `{true}`), and flagged no widening: from `signed_in` to
  `anyone` is one, for someone not signed in. It compares them now, as the reference evaluator reads them. And a
  difference for someone not signed in was said to be for "user (nobody signed in)".
- `rowstile review` said "nothing flagged" of a widening its own comparison had found ("not a refactor: ...
  differs for ..."), when the worlds Risk draws missed it. Risk takes that example too.
- `rowstile review` of a base written in the language before this one, with a mistake, gave the mistake this
  language finds first: an old form to write anew (`role app_user`). It gives the base's mistake, as the language
  it is written in finds it.
- `rowstile review --db` called a service a user: "1 user gains `view`" when a bot gains it, and "user bot:7"
  in the comment's examples, without how it gains (`authz.explain` was asked for a user of that name). Someone
  not signed in was a user too. It says "1 bot gains `view`", "bot 7" with how, and "someone not signed in".
- How someone gains, in the comment's examples, listed a condition that holds inside a part that doesn't:
  `{inherit}` in a `(parent.view and {inherit})` that doesn't hold. It lists only what grants it.
- `rowstile review --db` in a project without a lock file (`rowstile apply`, no migrations) said "the migration
  fails" when applying the policy on the review data failed, and Deploy said nothing of it, nor how long applying
  took. Both say what happened now.
- Ctrl-C while `rowstile sql` (or `can`, `explain`, `perms`, `list`, `who`, `explain-rule`) waited on a statement,
  or while `rowstile review --db` worked on its database, stopped only once the statement had run its course. It
  stops at once now and ends the statement on the server, as the other commands did.
- `rowstile init` on a schema whose users table is keyed by two columns (a tenant's and its own) asked which
  table holds the users, and naming it with `--users` then failed on its key. It says at once that the user
  table needs a key of one column.
- `rowstile review` of the pull request that adds the policy said its app role and its user type changed, from
  `app role app_user` and `type user = app.users`, which nobody wrote: with no policy at the base, it compared
  with a made-up one. Each declaration is now added, the app role and the user type too, and Meaning and Risk
  compare with a policy that allows nothing.
- `authz.create_role` made a role for a type without custom roles, or for one the policy doesn't have, when
  the role granted nothing: a role nobody could be given. Given a permission, it refused, saying roles there
  "cannot grant" it. It says "no custom roles on team in the policy" (AZ707) for both now. **Upgrading**: apply
  the policy again (or the next migration).
- `authz.can`, `authz.who` and `authz.explain` said "no type team in the policy" for a type the policy has but
  that has no permissions, and `authz.perms` and `perms_of` refused it the same way. They say "no permission
  team.view in the policy" now, as `authz.list` did, and `perms` gives none. **Upgrading**: apply the policy
  again (or the next migration).
- A condition in a select rule that Postgres refuses (a column the table doesn't have, say) was reported in
  Postgres's words alone, without its line: Postgres says no position in a row-level security policy's own
  expression. `rowstile apply` now names it with its line, as it does the others (AZ613).
- An `update after` rule on the whole row checked the row after an update without asking the scope (or
  view-as) whether it allows updates, where every other rule asks. Nothing was let through: the update rule
  itself asks, and Postgres only checks the row after for a row the update rule let it change. **Upgrading**:
  apply the policy again (or the next migration).
- `authz.can` failed with Postgres's "more than one row returned by a subquery used as an expression" for a
  key two rows hold: a governed table's primary key doesn't cover the rows of a table that inherits from it,
  so a key changed or inserted in one can be in the other too. So did `authz.perms`, `explain` and `who`,
  which ask it. A permission now holds on such a key where it holds on either row, as `authz.list` and the
  rules already said. Nothing was let through. **Upgrading**: apply the policy again (or the next migration).
- `rowstile prove` and the review's refactor check could read the column values of a world they had
  already left, kept under its address once another world took it: an invariant found broken that the
  world doesn't break (prove stopped on an internal check), or a world's answer missed. And a world where
  every condition holds could make `{archived}` and `{not archived}` hold on the same row: a corner now
  chooses each row's column values, and the conditions are read from them as in any other world.
- `rowstile prove` and the review's refactor check read a condition as a fact about the row only where it
  means the same whatever the column's type. Text in order (`{name < 'b'}`, which follows the database's
  collation), text Postgres reads as the column's number or boolean (`{size = '10'}`, `{done = 't'}`, `{kind
  in ('y')}`) and an order against `authz.uid()` are now left to the database, as a subquery is: a world may
  have any row pass them. They compared text by its characters, `'t'` with a boolean as text, and the ids a
  relation's column holds with a number as text: `{owner_id < 10}` was false for owner 2. Conditions made up
  at random are now asked of Postgres too, on the same rows, and must get the same answer.
- **Rows under a governed table.** Rowstile checks a rule on a column (`update owner_id : share`) with a
  row trigger, and forgets a row's shares when its key changes with another. Three kinds of rows escaped
  them. An app with neither partitions nor tables that inherit was not affected.
  Security advisory [GHSA-h92j-8v4p-93hc](https://github.com/rowstile/rowstile/security/advisories/GHSA-h92j-8v4p-93hc).
  - *A partition made after the policy was last applied* (by a job that makes next month's, say): the rule
    on a column was not checked on its rows, so someone who may update a row could change a column the
    policy keeps for others. The trigger asked whether row-level security applies to the partition, where
    rowstile turns it on at the next apply; it now asks of the table, and the rule holds on a partition
    from the moment it is made.
  - *A table that inherits from a governed one* (`CREATE TABLE ... INHERITS`): Postgres runs a table's row
    triggers for its own rows and its partitions', not for the rows stored there. No rule on a column was
    checked on them, a key change kept their shares, and the audit had no line for a relationship column
    changed there. Applying now gives each such table its table's row triggers, and `authz.lint()` reports
    one made since the last apply.
  - *A row an update puts in another partition*: Postgres runs no `AFTER UPDATE` row trigger for it. A key
    change kept its shares, so a row that took the old key later started with them, and the audit missed
    its changed relationship columns. A partitioned table now forgets the shares of every key an update
    leaves without a row, and audits the rows it moves.

  And `rowstile apply` applies when a partition, or a table that inherits, was made since the last apply:
  it answered `unchanged` and left it as it was, though `authz.lint()` said to apply again.
  **Upgrading**: apply the policy again (`rowstile apply`, or the next migration). The limits page says
  what stays a limit.
- A rule on a column whose permission involves a service (a principal type other than `user`: `update
  owner_id : bot`, or a permission a bot's relation feeds) could be passed by nobody: every update of that
  column through the app role failed with Postgres's "permission denied for schema authz_int", for the
  service the rule names as for those it refuses. The trigger that checks the rule runs as the app role
  and named the signed-in service, which is not the app role's to name; the rule is now behind a function
  made once, as the refusals' are. Nothing was let through that the policy doesn't allow. (#108)
- `rowstile apply` also applies when someone was given a privilege on rowstile's own schemas since the last
  apply. `authz.lint()` said "the next apply takes it back", and `apply` answered `unchanged`: only `rowstile
  reapply` took it back.
- With a capital letter in a governed table's name, as Prisma names tables (`"Folder"`), `rowstile push`,
  `apply` and `dev` applied the whole policy every time: `apply` never answered `unchanged`, and `dev` did
  all the work again at each save. The command looked for what the policy made under the tables' unquoted
  names, and found nothing. (#95)
- The Next.js page says which Prisma to install, where `instrumentation.ts` goes when `app/` is inside
  `src/`, how a route handler shares (`db.$authz.share`), and has the development database's step in the
  migration commands. The stack pages and troubleshooting no longer say that `rowstile migrate --check`
  tells what a database holds: it compares the policy with the lock file. (#99)
- `rowstile review`: "2 checks changed what they expect". It said "what it expects" of several.
- `rowstile review` no longer reads a test's new name as its checks removed. A test that went away, whose
  every check is in one that appeared, is said to be renamed, and its checks are compared under the new name:
  "1 test renamed. 2 checks changed what they expect", where it said "8 checks removed". The JSON has the
  names under `tests.renamed`.
- A rule that names a relation to objects alone (`select : owner or parent`, where `parent.view` was meant) is
  refused with AZ301, as it was when the relation has one source, also when it has a column and a link table.
  It compiled, and gave no one anything through the relation: `delete : owner and not parent` let owners delete
  every row they own, whatever its parent.
- A deny on a permission that inherits through another type's permission (`can view = (owner or parent.view or
  project.view) and not hidden`, where projects inherit from folders too) is refused saying so: "folder.view has
  a deny, so it can only inherit within folder" (AZ306). It said "folder.view depends on itself" (AZ302), and
  nothing of the deny.
- `rowstile indexes` asked for indexes on a view that a relation reads (`app.members(team_id -> user_id)`,
  `app.members` a view), with a `CREATE INDEX` that Postgres refuses, so `indexes --check` could never pass. A
  view can't have an index: the tables under it answer its lookups, as `authz.lint()` already said. `rowstile
  dev` warned of them at start too.
- `rowstile indexes` gave a partitioned table's missing index as `CREATE INDEX CONCURRENTLY`, which Postgres
  refuses on a partitioned table ("cannot create index on partitioned table concurrently"). It says `CREATE
  INDEX` there, which makes the index on each partition.
- `rowstile bench` left out a path that failed, without a word: with the app role not allowed to read
  `app.files`, the reads and updates of `app.files` were simply not in the table. They are there now, with
  what the database said: `read app.files  -  -  <- failed: permission denied for table files`.
- `rowstile init` didn't find FastAPI or SQLAlchemy in a `pyproject.toml` whose dependencies are all on one
  line, each with its version in parentheses as Poetry writes it (`"fastapi (>=0.115.0,<0.116.0)"`), or given
  by a URL (`"fastapi @ git+https://..."`): it wrote no setup line and asked for `rowstile` without its extras.
- `rowstile init`'s draft said "the loop of foreign keys it is in has no owner anywhere" of a table whose
  only foreign keys point at a table nobody changes through the app (products in categories), where there
  is no loop. It says "nobody edits what it is in" there.
- `authz.lint()` failed on a type keyed by two columns that sits in a tree by both (`parent : folder =
  [org_id, parent_id]`) when no `update ... after` rule checks where a row moves: "column "org_id, parent_id"
  of relation "folders" does not exist". `rowstile apply`, `push` and `dev` ask lint as they apply, so such a
  policy couldn't be applied at all. Lint names the pair now, with the rule to add (`update org_id, parent_id
  after : parent.edit`). **Upgrading**: apply the policy again (or the next migration).
- `authz.lint()` took an index with a condition (a partial index), or one that a failed `CREATE INDEX
  CONCURRENTLY` left unfinished, for one that serves a lookup the permissions make, and said nothing of a
  lookup that reads the whole table. `rowstile indexes` didn't count them, and lint doesn't now. **Upgrading**:
  apply the policy again (or the next migration).
- A connection string of keywords (`host=... dbname=...`) is split into its settings as libpq splits it:
  spaces around `=`, a quote in a value written `\'` (`password='it\'s'`), and a `"` as it is. Those were
  refused. And `password='it''s'`, which the command's own message suggested, was read as `its`; it is refused
  now, as psql refuses it.
- Several hosts (`host=a,b`, or `postgresql://a:5432,b:5432/db`) are refused, saying the command connects to
  one. They failed with "Name or service not known", or in a URL with a message about a `#` in the password.
- `rowstile sql` showed an array of arrays of text or booleans wrong: `ARRAY[['a','b'],['c','d']]` as
  `['{a', 'b']`, and booleans all false. It shows them as Postgres writes them, braces in braces, as it did
  numbers.
- `rowstile mcp` takes a batch, an array of requests, as protocol version 2025-03-26 asks a server to: each
  request in it is answered, in an array. It answered "not a request". A request whose id is null gets an
  error, where it got no answer and its client waited. Params that aren't an object, and a tool's argument
  that is null, true, an object or a list where text goes, are refused: they were taken as no params, or
  passed to the command as `None`.
- The command connects as libpq does with the same settings, and refuses, naming it, a setting it doesn't do,
  where it left some out. With `channel_binding=require`, a server that asks for the password in clear or hashed
  with MD5, offers SCRAM without channel binding, or signs the command in without asking is refused before
  anything is sent to it. With `sslmode=require`, the server's certificate is checked against a root certificate
  when there is one (`sslrootcert`, `PGSSLROOTCERT`, or `root.crt` in libpq's folder: `~/.postgresql`, or
  `%APPDATA%\postgresql` on Windows), as `verify-ca` checks it. `sslrootcert=system` checks it against the
  system's roots and checks its name, as `verify-full`, and a weaker `sslmode` with it is refused. A certificate
  `sslcrl`, `sslcrldir` or `root.crl` lists as revoked is refused. `require_auth`, `target_session_attrs`,
  `ssl_min_protocol_version` and `ssl_max_protocol_version` are honoured, and so are `PGCONNECT_TIMEOUT`,
  `PGREQUIRESSL`, `PGDATESTYLE`, `PGTZ` and `PGGEQO`. What it doesn't do is refused, from a connection string or
  a variable: a service (`PGSERVICE`), a host address apart from its name (`hostaddr`), client certificates
  (`PGSSLCERT`), GSS encryption (`gssencmode=require`), a password file where no password is given
  (`PGPASSFILE`), and the like. **Upgrading**: `sslmode=verify-ca` or `verify-full` with no root certificate,
  which the command checked against the system's roots, now needs one, as in libpq: `sslrootcert=system` with
  `verify-full` for a server whose certificate a public authority signed.
  Security advisory [GHSA-g2rq-h47r-5v2c](https://github.com/rowstile/rowstile/security/advisories/GHSA-g2rq-h47r-5v2c).
- `rowstile review` and `rowstile prove` missed two kinds of widening. One behind a long `and` of links:
  `can approve = owner and legal and finance and security and privacy`, five link tables, changed to `(owner or
  editor) and ...`, was "Meaning unchanged" with nothing flagged, and `never doc: approve and not owner` was said
  to hold. And one that only a chain of more than four objects shows: a share that reaches three folders down,
  widened to four. The small worlds they try now include dense ones, where half the links, three quarters or
  nearly all of them hold, and, for a policy that reads two links deep or more, chains one link longer than it
  reads (at most ten objects). Both take about a fifth to two fifths more time; `rowstile prove` says how large
  its largest world was.
- `rowstile check`, and everything that compiles a policy, stopped with a Python traceback (`KeyError: 'anyone'`,
  or `'link'`) on a permission that follows a relation shared with `anyone` or a link: `pub : anyone shared by
  edit` with `can view = pub.see`. It says what `user:*` there got: AZ301, there is nothing to follow.
- `rowstile prove`, `rowstile review` and `rowstile why` stopped with a Python traceback (`ValueError`) on a
  condition holding a whole number of more than 4300 digits, which Python won't read. Such a condition is the
  database's to read, as a subquery is.
- `rowstile migrate` for Alembic took a merge revision's two parents for heads too when its `down_revision` is
  laid out over several lines, as black and Ruff lay out a long tuple, and refused: "several heads: merge them
  first". The merge is the head.
- Studio's access diff of a policy file with an expression nested too deep to read answered with Python's words
  (500), and a traceback where Studio runs (`rowstile dev`'s terminal): it says what the command says, "an
  expression in the policy is nested too deep to read".
- Studio answered a request body nested too deep (`[[[[...]]]]`, a hundred thousand levels, or a field a few
  hundred deep) with Python's words (500), and a traceback where Studio runs. It answers 400, "missing or wrong:
  the body is nested too deep to read", as it answers a body that isn't JSON.
- Four things the docs promised were said wrong. The threat model said a condition in `rules` runs with the app
  role's privileges: a condition reads with the policy's rights in rules as in permissions, as the language's
  page says. It said the change feed was append-only for everyone: the app role can't touch it, and the
  administrators may trim it. An API key's first ten characters are kept beside its hash, to tell keys apart,
  where the identity page said only the hash was. And `rowstile review` without `--base` compares with `main`
  (or `master`): it exits 2 only where there is neither, not whenever `--base` is left out. Each promise of the
  reference, the threat model and the page on how rowstile is checked now names the check that holds it, and
  every code block of the reference runs (`core/tests/reference.sh`).
- Two tables whose rules named the same view (`rules app.folders view app.visible` and `rules app.files view
  app.visible`) passed `rowstile check`, and `rowstile apply`, `push` and `migrate` stopped with a Python traceback
  (`ValueError: view "app"."visible" is made twice`). It is refused when the policy is compiled, naming both lines
  (AZ109).
- Conditions that only a function reads were not read when applying: the `where` of the user type, or of another
  type that signs in (who is signed in reads it), and a relation's `shared if {...}` (`authz.share` reads it). One
  that doesn't run, a column that isn't there say, was applied without a word, and then failed every query of the
  app (`authz.uid()`), or every share of the relation. Applying reads them now, and refuses one that doesn't run
  with its line (AZ613), as it does the other conditions. **Upgrading**: for a policy with such a `where` or
  `shared if`, `rowstile migrate` writes a migration: those functions made again, and read.
- A caveat that doesn't run (a column that isn't there), when it reads what its share was made with
  (`arg('ip')`), was said as another condition's mistake: applying named the policy's other caveat, or no line
  at all. It names the caveat's line.
- A lock file with a merge's conflict markers in it (two branches that each wrote a migration) stopped
  `rowstile migrate` with a Python traceback (`IndexError`), and `rowstile review` too when the base branch's
  lock had them. `migrate` says which line it can't read and what to do (AZ619), exit 1, and writes nothing; the
  review says why its Deploy part isn't computed, and goes on.
- `rowstile indexes` said every lookup had an index when a relation reads the row's own key and nothing indexes
  that key: a table keyed by its user's id, with `owner : user = user_id`, and no primary key. Lists find those
  rows by the key, with a full scan. It names that index now, as `authz.lint()` did, and `rowstile dev` warns of
  it at start.
- `@rowstile/prisma`: a `findFirstOrThrow` that finds no row named a value of its filter as the row's key in
  the 404: `where: { id: { gt: 5 } }` said `app.notes 5 not found`, and `where: { body: "x" }` said `app.notes x
  not found`. It names the table, and the id only when the filter is one (`where: { id: 5 }`).
  `findUniqueOrThrow` names the key as before.
- `@rowstile/prisma`: a `findUniqueOrThrow` by a key that is a date (a `DateTime` field that is the model's id,
  or unique) that found no row named the row `()` in its 404: `public.holiday () not found`. The SDK can't
  write a date as the database does, so the 404 names the table alone, as for a key with a date among its
  fields.
- `@rowstile/next`: an event stream (`authzRoutes`' `events`) whose page went away stopped listening to the
  change feed twice, once when its stream was cancelled and again when its request was aborted (and once more
  for a change told after that): a feed of your own given as `changes` was unsubscribed as many times. Once
  now.
- `@rowstile/next`: an access request without a reason, sent to `authzRoutes`' `request` route (what the React
  kit's `useAccessRequest` calls), answered 500, and `useAccessRequest` failed with "Internal Server Error". It
  answers 400 with the database's words, "say why you need it", and code AZ710 (a problem body of the new type
  <https://rowstile.dev/problems/bad-argument>), which `useAccessRequest` fails with.
- `rowstile.sqlalchemy`: `why_stale()` could answer about a write another thread made outside a request or
  `acting_as` block, naming its row. The ORM's writes outside a block (an engine `install()`ed with `user=`, as
  in a Flask app or a worker thread) went to one list for the whole process. Each thread (or task) now has its
  own, for the transaction it began last: a later transaction isn't answered about an earlier one's writes,
  and a block that wrote nothing isn't answered about writes made outside it. In `rowstile.fastapi` each
  request has its own, also when `Rowstile` isn't given `user=` (a sync endpoint's refused flush is 403).
  Security advisory [GHSA-fwpc-v7vf-5qf7](https://github.com/rowstile/rowstile/security/advisories/GHSA-fwpc-v7vf-5qf7).
- `rowstile why` (and Studio, where it may write) didn't offer to share again where a share had expired, starts
  later or has a caveat: it tried it as the share already there, which granted nothing. It tries it as
  `authz.share` makes it again. It offered a share the relation's `shared if` refuses, which `authz.share`
  refuses too: it offers only the ones it allows.
- `rowstile why` and Studio offered no column and no link row on a type keyed by several columns (`type project
  = app.projects (org_id, id)`): "no single change to shares or links grants it", where setting the project's
  `lead_id`, or adding a row to its members' table, would. They offer both.
- `rowstile why` called a condition after `not` (`and not {archived}`) a deny. It names the condition.
- `rowstile why` (and Studio, where it may write) said only part of what a change gives: the permission asked
  about on more objects of its type, and the others on the object itself. Making someone the owner of a folder
  higher up said "also gives edit on it, and share on 3 more folders", and nothing of the edit it gives on those
  folders or of the files in them; making someone an org's admin didn't say they could then impersonate its
  members. It says every permission the change gives them, on every object, and the change that gives the least
  comes first.
- Where a group inside a group is said by the group's own row (`member : team#member = app.teams(parent_id ->
  id)`), `rowstile why` tried to add a row for a team that is there, which can't be done: "could not be tried:
  add team 10 to app.teams for team 11 (null value in column "org_id" ...)". It doesn't try that: putting a team
  inside another moves it out of where it is.
- Studio, where it may write, left out the changes the database refused to try. Where `rowstile why` said "no
  single change that could be tried grants it" and "could not be tried: add user 3 to app.doc_editors for doc 5
  (null value in column "added_by" ...)", Studio's page said "No single change to shares or links grants it". It
  says them, with the database's reason, as the command does.
- `rowstile why` on an object that isn't there (`doc 999`), or an id its key can't hold (`doc five`), tried the
  changes on it anyway: "no single change that could be tried grants it", and a "could not be tried" line for
  each one the database refused (invalid input syntax for type bigint). As someone who isn't there (`--as
  user:999`), the same. It says "there is no doc 999", as `authz.share` says of someone who isn't there, and
  tries nothing. A row the type's `where` leaves out (an archived folder) holds nothing: where it said no change
  grants it, with notes on other conditions, it says "folder 7 fails the type's where {not archived}".
- `rowstile why` and Studio named a type or a permission the policy doesn't have in words of their own ("folder
  has no permission fly"), and took a relation, which `authz.can` and `authz.explain` refuse. They refuse what
  those refuse, in their words and with their code: "no permission folder.fly in the policy", `rowstile help
  AZ707`.
- Studio, where it may not write, gave a service no explanation of why not, where the command gives the
  database's, and listed changes for an object that isn't there. It answers as the command does, the changes
  listed and none tried.
- `rowstile why` judged a relation's `shared if` with nobody signed in. A condition that reads who shares
  (`shared if {subject_id <> authz.uid()::text}`) then refused every share, and `why` offered none, where
  `authz.share` run by the object's owner makes it. It judges it as `authz.share` does, as someone who may share
  the object. Where nobody may share the object, or nobody who may passes the condition, it offers no share
  there and says why in a note.
- What a change takes from other people covered only the permission asked about, on the object asked about:
  making someone else the owner of a doc said nothing of the share, edit and archive its owner loses. `rowstile
  why` (and Studio, where it may write) says every permission they lose, on the object and on others: "(takes
  archive, edit, share on it from 1 person)". The people counted are those in what the change replaces (the
  owner a column names now) and, where a deny reads what it gives, those in the group it gives it to.
- `rowstile why` and Studio offered changes that change nothing: setting the owner an object already has, beside
  the change that grants it ("set owner_id of room 1 to 1 and ..."), or on its own where Studio may not write;
  adding a link's row that is there ("could not be tried: ... duplicate key"); a share that is there. They offer
  only changes that change something.
- To say all a change gives, `rowstile why` (and Studio, where it may write) counted every permission of every
  type before and after each change. It counts only the permissions a change can reach: those that read what it
  writes, worked out from the policy.

What changed since 0.1.0-alpha.5:

### Added

- Tests can check a line as a key or a token limited to a scope would be: `with scope` after who the line is
  about, `user 3 with scope read cannot edit file 11`, `as user 3 with scope read, files refused {UPDATE
  ...}`. A scope the policy doesn't have is a mistake when the tests compile (AZ503). The editors' grammars
  know the words (the VS Code extension is 0.1.2).
- A recipe: [API keys limited to some permissions](docs/cookbook/api-keys-with-scopes.md), which those
  tests make possible. The cookbook has nineteen.
- `rowstile init` leaves a note for the coding agents that work in the app, in `AGENTS.md`: where the policy
  and its tests are, the loop after an edit, that production takes migrations, that the app connects as the
  app role and signs each transaction in. Without it an agent sees a route with no permission check and adds
  one. The note sits between two markers: an `AGENTS.md` that is there keeps its text and gets the section at
  its end, and one that has the markers is left as it is.
- Each `@rowstile/*` package has a page of its own on npm: what that package is for, its install line,
  code from the tested Next.js app, and links to its stack's page. All eight showed the SDK's one
  README.
- `authz.lint()` warns of a rule for a command the app role has no privilege for on the table (`update :
  manage` on a table it may not `UPDATE`): the rule never applies, and the statement fails with Postgres's
  own "permission denied for table", which reads like the policy refusing. It says what to grant. A privilege
  on one column is enough; `nobody` asks for none.
- A page per alternative, each with examples in both and a section on when the other is the better
  choice: [OpenFGA](docs/compare/openfga.md), [SpiceDB](docs/compare/spicedb.md),
  [ZenStack](docs/compare/zenstack.md), [row-level security by hand](docs/compare/hand-written-rls.md) and
  [checks in app code](docs/compare/app-code.md).
- A blog, with an Atom feed (`/blog/feed.xml`). Its first article:
  [Why a recursive row-level security policy is slow, and what fixes
  it](docs/blog/2026-10-07-recursive-row-level-security.md), with the experiment to run it again.

### Changed

- A refused write reads the same wherever it is said. An UPDATE or DELETE that changed nothing (the
  SDKs' `expect`, Prisma's and SQLAlchemy's writes of a row the user may not change, the generated
  clients) is `permission denied: user 3 may not update row 7 of app.notes`, like the database's own
  `user 3 may not insert this row into app.notes`. It was `may not update app.notes 7`, without who. Who
  is asked of the database, in the same transaction. A key of several columns is written as the database
  writes it, `(1,2)`, in `Refused`, in `NotFound` and in its `id` (Python wrote `(1, 2)`, TypeScript
  `("1","2")`). Generated clients: write yours again (`rowstile client py`).
- `authz.lint()` notes a relation named like a type only when that type signs in (`user : user = owner_id`:
  alone in a rule, `user` reads like any user). A relation named like another type, as `rowstile init` drafts
  and getting started writes (`project : project = project_id`), is only ever followed (`project.edit`) and
  gets no note.

- `rowstile sql --as` says what a statement that returns no rows did, in the server's words (`UPDATE 0, as
  user:2; rolled back`): "done" read as allowed when the rules had let it change nothing.
- A policy's Alembic revision stops in one line when Alembic is connected with asyncpg (which takes one
  statement at a time), naming the sync driver to give it, instead of the driver's error with the whole
  script in it.
- `rowstile init`'s draft writes an insert rule with the relation (`insert : project.edit and author`), not
  its column again (`{author_id = authz.uid()}`), and for folders inside folders lets a row with nothing
  above it be made, in the maker's own name (`insert : owner and (parent.edit or {parent_id is null})`):
  with "inside one you edit" alone, nobody could make the first one through the app.
- The coverage line of `rowstile dev` and `rowstile test --coverage` names the checks that count: "7
  branches no "can" check reaches". A statement run `as` someone passes and covers nothing.
- The FastAPI page's install line is `uv add "rowstile[...]>=0.1.0a0"`: it takes rowstile's pre-release and
  no other package's, where `--prerelease=allow` also brought betas of the app's own dependencies.
- The cookbook's folders recipe lets anyone start a top-level folder of their own
  (`insert : owner and (parent.edit or {parent_id is null})`): with `parent.edit and owner` nobody could make
  the first folder through the app.

### Fixed

- `rowstile review` says "1 user gains" (it said "1 user gain"), and names the difference that makes a
  change no refactor as its risks name theirs: "differs for user 1 on note 1" (it said "for 1 on 1").
- `rowstile why` (and Studio) tries a row in a link table for a relation with a `where`, with the values
  the condition asks (`add user 4 to app.project_members for project 1, with role = 'admin'`), or the
  change to the row that is there already (`set role = 'admin' on user 4's row of ...`). It ended with "no
  single change to shares or links grants it" where one row would. A condition that is more than columns
  with values isn't tried, and a note names the relation left out.
- `authz.lint()` no longer warns about a column a relation reads on a table whose rule is `update : nobody`,
  and the rule it suggests for such a column names `share` only where the type has it (`nobody` otherwise:
  the suggestion didn't compile on a type without `share`).
- `rowstile init` names the policy's app role in what it prints and in the first test file (it said
  `app_user` whatever `--role` was), doesn't ask to add `rowstile` to a project that has it, finds FastAPI
  and SQLAlchemy when they come through rowstile's own extras, and in a Prisma project shows the app's
  client on a URL of its own (`ROWSTILE_APP_URL`), not on Prisma's `DATABASE_URL`, which is the owner's.
- With no `--db`, no `database` in `rowstile.toml` and no variable, a failed connection says that no database
  was named and how to name one (on Windows it said `host=/var/run/postgresql is a Unix socket`).
- `rowstile dev`: an error after the policy went in (the tests' switch to the app role refused, AZ618) ends
  with "the policy is applied; its tests didn't run", not "nothing applied". AZ618's hint says who may run
  the grant when the owner didn't make the app role.
- The Next.js page shows the migration that makes the app role and its grants, Prisma's configuration on the
  owner's URL, and what to do on a development database that `rowstile dev` pushed to before
  `prisma migrate deploy` (AZ607: `prisma migrate resolve --applied`); `rowstile help AZ607`, the
  migration's own hint and the troubleshooting page say the same for each tool.
- A test line `as user X sees N {UPDATE ...}` is refused when the tests are compiled, saying that `sees`
  counts a SELECT's rows and that a write which must change no row is `refused` (it was a bare "syntax
  error" when the tests ran).
- `rowstile dev`'s access line reads "2 user(s) gain permission comment on 1 project" (it said "on 1 of
  project").
- `rowstile help` for a code the runtime raises (AZ701 to AZ713) ends with its own code, not AZ709's.
- The FastAPI page shows the imports its code uses; getting started says the draft is replaced, not edited,
  and what its Python example needs; the language page says how a condition names a column with capital
  letters.

What changed since 0.1.0-alpha.4:

### Added

- The cookbook is eighteen recipes, each a page with its own tables, policy and tests and a link that opens
  it in the playground: tenants, roles, teams inside teams, folders that inherit, sharing and links, access
  on request, a masked column, archive and trash, bots, blocking ([the cookbook](docs/cookbook.md)).
- Two pages: [rowstile and the alternatives](docs/comparison.md), and
  [how rowstile is checked](docs/how-it-is-checked.md).
- The packages say what they are on npm, PyPI and ghcr.io (keywords, links, labels), and the site has a
  sitemap, a description per page and a card for shared links.
- Each release publishes the MCP server's entry (`rowstile mcp`) to the official MCP registry, as
  `io.github.rowstile/rowstile`, so clients that find servers there can add it by name. The entry names the
  npm package.

### Changed

- The VS Code extension (0.1.1) has an icon, keywords and a link to its page on rowstile.dev. Nothing in
  what it does changes.

### Fixed

- `rowstile indexes` and `rowstile dev` named indexes as missing on tables whose name has capital letters
  (`"TeamMember"`, as Prisma writes them): the table was looked up by its name unquoted, and never found.
- `@rowstile/prisma`: `findUniqueOrThrow` and `findFirstOrThrow` on a row that isn't there, or that the user
  can't see, threw Prisma's own error, which `route()` answered with a 500. They throw `NotFound` (404), as
  an update or a delete of such a row does.
- On Windows, in a project whose path is so long that the Python inside the npm package can't be loaded,
  `npx rowstile` stopped with a Python traceback ("DLL load failed ... The filename or extension is too
  long"). It now runs on a Python 3.11 or later from `PATH`, and without one says what is wrong in a line.
- `rowstile[psycopg]` installed a psycopg that can't be imported where the system has no libpq (Windows):
  the extra asks for `psycopg[binary]`.
- The FastAPI page didn't say that Alembic needs a sync driver (the policy's revision fails on asyncpg with
  "cannot insert multiple commands into a prepared statement"), that the owner must hold the app role, or
  what to do with a development database `rowstile dev` pushed to. It says all three.
- The getting-started guide began in a clone of the repository: it now begins with the installed command
  and any Postgres, and keeps the clone as the other way. It says that the `SET ROLE` session of step 6 is
  a trusted one, where a forgotten sign-in gives no rows and not the error an app's connection gets.
- The Next.js and Node pages' install lines asked for the alpha of the command only, so the SDK packages
  came at an older alpha than the command. Every line asks for `@next` while only alphas are published.

What changed since 0.1.0-alpha.3:

### Changed

- `@rowstile/prisma` (security advisory
  [GHSA-6g93-673q-c29f](https://github.com/rowstile/rowstile/security/advisories/GHSA-6g93-673q-c29f)): a
  Prisma extension added to the client `authz()` returns is placed before `authz()`,
  which stays the last one. Your query hooks then see the errors `authz()` makes (`Refused`, `NotFound`) where
  they saw Prisma's `P2025`.

### Fixed

- `@rowstile/prisma`: the client `authz()` was made from is refused inside your own query extensions too. In a
  hook added after `authz()` it was let through, and Prisma could then answer the `findUnique` calls that
  several requests made on it in one tick with one query, signed in as the first caller: a request could be
  given a row its user may not see. An app that only uses the client `authz()` returns was not affected.
- `@rowstile/prisma`: a query hook of yours runs once for a `findUnique` or a `findUniqueOrThrow`. One added
  before `authz()` ran twice; one added after it was not called at all, so a filter it added was skipped.
- On Windows, three commands ended in a Python traceback when two paths were on different drives. `rowstile
  review` now works from a `subst` drive or a folder reached through a junction (it stopped with test files
  named in `rowstile.toml`, and with `--annotations`); for a policy on another drive than the one it runs on,
  it reviews the whole policy as new, as for any file outside the repository. `rowstile migrate --dir` with a
  folder on another drive wrote the migration and the lock file, then stopped: it now finishes. Studio shows
  such a policy's path as it is.
- `rowstile migrate` no longer adds a line to `.gitattributes` for a migrations folder or a lock file outside
  `rowstile.toml`'s folder: such a line (`../migrations/*_authz_*`) matches nothing.
- On Windows, the command's output is UTF-8 when it goes into a file or a pipe (CI, `rowstile review --markdown
  > comment.md`, `rowstile graph > policy.mmd`), as it already was in a terminal. Python wrote it in the
  system's code page: a character that page lacks (an arrow, a name or a text in another script, in a
  condition) stopped `review`, `prove` and the others with `UnicodeEncodeError`, and the files written were not
  UTF-8.
- `rowstile review` finds, at the base, a test file whose name has an accent or another non-ASCII character (it
  read the base as having no such file, so its checks showed as added), and reads a base file that isn't UTF-8
  with the bytes it can't read replaced (on Linux and macOS it stopped with a traceback).
- `rowstile review` says when a test file of the pull request doesn't parse, with the mistake. It compared the
  policies without any test file then, and said "no change to what the tests claim". A check that changed is
  shown on its own file's line (`tests/docs.authz line 12`), no longer on a line counted from the policy's top.
- `rowstile explain-rule --row` shows a row that isn't JSON as it arrived. Windows PowerShell 5 and cmd take
  the double quotes out of `'{"project_id": 1}'`, and the message was JSON's own ("Expecting property name
  enclosed in double quotes"): it now says the shell took them, and how to write the row there.
- `rowstile review` flags a relation that is newly shared once. It said so once for each kind of subject the
  relation may be shared with (`viewer : user, team#member, org#member shared`: three times, word for word).

What changed since 0.1.0-alpha.2:

### Added

- The VS Code extension is on the VS Code Marketplace too, as `rowstile.rowstile` (a preview, like on Open VSX).
- The Python SDK copies the migrated test database for each pytest-xdist worker, as `@rowstile/vitest` does
  for Vitest's: `rowstile.testing.database_per_worker(url)` returns the copy's URL (and the app role's), so
  tests that write don't meet each other. It needs no driver of the app's.
- `authz.list_links(type, id)` lists the share links on an object (an id, the relation, who made it, when,
  until when) and `authz.revoke_link(type, id, link)` turns one off by that id, so an app no longer keeps a
  table of its own to do it. For people who can share the object, or may make such links. The generated
  clients have them as `list_links` and `revoke_link` (`listLinks`, `revokeLink`).
- The Python SDK's queries by permission take the policy's names: `rowstile.sqlalchemy.Queries[ObjectType,
  Permission]()`, with the generated client's two types, has `ids`, `can`, `can_sync`, `perms_of` and
  `perms_of_sync`, and a misspelled type or permission no longer type-checks. The functions that take any
  string stay.

### Changed

- Reads plan faster in policies with tiers that inherit. With `can edit = manage or editor or parent.edit` and
  `can view = edit or viewer or parent.view`, the view of `view` looked up `parent.view`, `parent.edit` and
  `parent.manage`, and each did the same one type up, so what Postgres planned for a read grew with the number
  of ways down through the tiers. It now looks up `parent.view` alone, which includes the others. Five types
  in a chain with three tiers: from 85 views and 13 ms of planning for each read to 20 views and 1.9 ms; seven
  types with four tiers: from 519 views and 179 ms to 36 and 6.7 ms. Who holds what doesn't change, and no
  policy has to.

### Upgrading

- The next `rowstile migrate` (or `apply`) replaces the views of permissions that name others of their type:
  a migration with no change to the policy.

What changed since 0.1.0-alpha.1:

### Added

- The docs site, at https://rowstile.dev: the guides, the reference, the error codes and the playground,
  as of the latest release.
- The VS Code extension is published on Open VSX, as a preview, by the release workflow whenever its own
  version is new (VSCodium, Cursor, Gitpod and other editors install from there).

### Changed

- The name: rowfence is rowstile (above). What it writes says rowstile: the hints of the errors the runtime
  raises (`rowstile help AZ709`), `rowstile graph`'s first line, the generated clients, the compiled SQL, and
  the comments that mark its own RLS policies and masked views in the database (`'rowstile'`,
  `'rowstile masked view'`). The SDKs still read the code from the hints of a database applied by rowfence.
  The problem bodies the SDKs write have their `type` at rowstile.dev (`https://rowstile.dev/problems/refused`).
- The Zed extension carries the licence in its own folder, as Zed's registry asks, and when `rowstile` isn't
  on the PATH it points to the Installing page (the install lines it showed get the placeholder while only an
  alpha is published).
- The compiler's script in the repository is `core/compile_policy.py` (it was `authzc.py`).

### Upgrading

- Install `rowstile` in place of `rowfence`: `pip install --pre rowstile` (or `rowstile[fastapi]`, ...), `npm i
  rowstile@next` and `@rowstile/*` in place of `@rowfence/*`; in Python, `import rowstile` in place of
  `import rowfence`.
- Rename `rowfence.toml` to `rowstile.toml`. Until then the command reads `rowfence.toml` and says so. The npm
  launcher reads `ROWFENCE_PYTHON` when `ROWSTILE_PYTHON` isn't set. The GitLab review template's variables
  are `ROWSTILE_REVIEW_TOKEN`, `ROWSTILE_VERSION` and `ROWSTILE_PACKAGE`.
- The next migration (`rowstile migrate`) marks the RLS policies and masked views anew; until then the command
  still recognizes the marks rowfence wrote (`'rowfence'`, and `'authzc'` before them). The next
  `rowstile client` rewrites the clients' first line.

### Fixed

- The policies readers copy (the docs app, the cookbook, the example apps' policies and tests) are laid out as
  `rowstile fmt` writes them, so `rowstile fmt --check` in CI passes on a copy; only spacing changed.
- While only an alpha is published, a plain `pip install rowstile` finds nothing: `rowstile init` now tells a
  Python app to add `rowstile[...]>=` its own version (which lets pip and uv take a pre-release), and the stack
  pages, the Python SDK's README and `llms.txt` ask for the alpha (`--pre`, `rowstile@next`,
  `uv add --prerelease=allow`).

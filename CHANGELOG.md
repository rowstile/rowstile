# Changelog

What changed in each release, newest first: a section for each, an alpha, a beta or a release candidate as much as
a final release. An alpha (`0.1.0-alpha.1`) is for trying a version early: it may still change before that
version is released. A beta (`0.1.0-beta.1`) is the version complete enough to use before it is released: it may
still change where using it shows a need. Before 1.0, a minor release (0.2.0) may change the policy language, the
`authz.*` functions, the SDKs and the file formats: what to do about it is under **Upgrading**. Each release from
0.1.0-beta.1 on upgrades from the one before it. How releases are numbered and made: [RELEASING.md](RELEASING.md).

## Unreleased

### Added

- `rowstile client ts-sdk`: the policy's names alone, registered with the TypeScript SDK, asked for by name. It is
  what `[clients] ts` writes in an app on the SDK; `rowstile client ts` is the client for `pg` without it.
- `authz.sign_out()`: nobody is signed in in the transaction afterwards, and it may sign in again, as anyone. It
  is for a test's transaction that acts for one person, then another, and is rolled back at the end; the SDKs'
  test modes call it ([Identity](docs/reference/identity.md)).

### Changed

- The database holds a transaction to one principal: `authz.act_as`, `authz.login_key` and `authz.login_jwt`
  refuse to sign in a transaction signed in as someone else already (nobody included), or one that views as
  someone or is limited by scopes, which a new sign-in would end (AZ716). A first sign-in after
  `act_as(NULL, NULL)` is still fine, and so is the same principal again. `view_as`, and `who`, `explain`,
  `who_among` and the invariants, which ask as others and put back the caller, aren't held to it, nor are the
  sessions of the policy's owner and superusers.
- The Rust SDK's `rowstile::testing::per_binary` refuses an app role's URL that isn't a Postgres URL, instead of
  giving it back as it was.
- The Rust SDK's `per_binary` gives each slot of cargo-nextest (`NEXTEST_TEST_GLOBAL_SLOT`) a copy of its own, as
  each binary has under `cargo test`.
- Seeing who has access to an object (`authz.who`, `authz.list_shares`, `authz.list_links`, `authz.explain` for
  someone else, `authz.start_review`) takes `share` on a row the user may select, and `authz.who_among` lists those
  for whom `authz.can` says yes (below). What acts on an object still asks the permission itself: sharing, roles,
  API keys, `authz.view_as` and `authz.break_glass`, which works on a row the user can't see. So do `authz.who`'s
  answers, the first line of `authz.explain`, `rowstile why` and a test's `user X can PERM TYPE ID`. The access
  previews (`rowstile diff`, the review's access, `rowstile dev`, `rowstile snapshot`) still list every permission
  gained or lost, on rows the user can't select too.
- `rowstile review` and `rowstile prove` work out what their small worlds read of a policy once, not in each
  world, and prove makes each world once for all the invariants: on the docs app's policy, reviewing a refactor
  takes a third less time, and proving four invariants a quarter of the time it did.
- `rowstile init` with `--db` and another `DATABASE_URL` writes `database = "env:ROWSTILE_OWNER_DSN"` in
  `rowstile.toml`, the name the stack pages give the tables' owner's connection, instead of
  `ROWSTILE_DATABASE_URL`. Its next steps name the variable `rowstile.toml` reads, not always `DATABASE_URL`.
- `authz.review_decide` refuses a decision after the review's deadline, the `closes_at` of `authz.start_review`
  (two weeks after it starts unless the call says otherwise; NULL: none), and says when it was (AZ718).
  `authz.close_review` still applies the decisions made in time. Before, the deadline was kept and never read.

### Removed

- `rowstile review --json`: `access.users_in_data`, which was always null.

### Fixed

- `rowstile init --role` refuses a name the policy's app role line can't hold (a space, a quote), before connecting.
  Before, it wrote a draft that didn't compile and a `CREATE ROLE` for another name.
- `rowstile init` without `--schema` leaves out the sync index's schema, `authz_sync`: its tables were drafted as
  the app's, and the roles granted them counted when it chose the app role.
- `rowstile init` reads `pyproject.toml` as TOML: its dependencies, optional ones, dependency groups and Poetry's
  tables. Before, each line's first word counted as a package, so any `pyproject.toml` made the app a Python one.
  It reads Alembic's `script_location` as Alembic does (`%(here)s` without a slash, a folder written with `\`), and
  for a package's (`myapp:migrations`) leaves `[migrations]` out, saying why. The paths it writes in
  `rowstile.toml` are TOML strings, so a quote or a backslash in one no longer makes the file unreadable.
- `rowstile client LANG` with no file is of the policy `rowstile.toml` names, as `rowstile graph` is and the reference
  says, with no database (but `powersync`, which reads the database `rowstile.toml` names); before, it connected and
  wrote the client of the policy in force. A language it doesn't write, or none with no `[clients]`, is refused
  before connecting. With no language, it says of each file that it wrote it or that it was up to date.
- `[clients] ts` is the names alone when the package.json nearest the client's file depends on `@rowstile/*`
  (`frontend/package.json` for `frontend/src/authz.ts`), looked for up to the git repository's top. Before, the one
  in `rowstile.toml`'s folder decided, or one above it, even above the repository. A package.json with a byte order
  mark is read.
- `rowstile client powersync`, a preview: a table the policy mirrors and the database doesn't yet is said, with
  what to do (apply or push first), instead of a traceback. Each stream's alias, the table's name on the client, is
  quoted, so a table named with a keyword (`app.order`) gives a stream the service takes. Two mirrored tables of
  one name in two schemas, which a client would name alike, are refused (AZ811).
- `rowstile graph` draws the user type's own relations: an arrow through one (`owner.manager`) pointed at a box the
  diagram didn't have.
- `rowstile client go`, `csharp`, `ruby`, `rbs` and `elixir` give no name to a type or a permission whose name there
  would be one the file or the SDK uses already, as for two names spelled the same: Go's `ObjectType` (object's
  `type`), C#'s classes `Permission` and `ObjectType` (which hid the SDK's), Ruby's modules `Rowstile`, `Hash`,
  `Array` and `String`, and Elixir's `Rowstile` and `Kernel`. Before, the file didn't compile. `rowstile client
  zero` names the readers tables of two types camelCase spells the same (`a_b`, `aB`) as each type is written.
- `authz.ctx(key)` is NULL for a key the transaction didn't set, also on a connection where an earlier
  transaction set it (Postgres then reads it as `''`), and for a key set to `''`: a condition or a caveat that
  reads the request context answers the same on a pooled connection as on a new one.
- `rowstile lsp` sends, when it reads the table and column names, the password in `rowstile.toml`'s database
  string or `PGPASSWORD` in `.env` beside it, not the editor's own `PGPASSWORD`: the folder opened names the host.
- `rowstile lsp`: in a test file with a mistake, hover, go to definition and find references still answer on its
  other lines. An included file's outline is its own types, not the policy's. Find references reads a `--` inside
  a condition's string as text, and completion offers a condition's columns on its later lines too. After
  `shutdown` a request is refused, and `exit` without `shutdown` ends the server with status 1, as the protocol
  says.
- `rowstile mcp`: `why` refuses an id the command would read as an option (`-h` printed its help; a negative number
  is still an id), and `test` refuses a `coverage` that isn't true or false (the text `"false"` turned it on). A
  call stopped after 600 seconds keeps what the command printed before it, so the agent sees where it was.
- The sync index, a preview: a PowerSync mirror (`mirrored`) is made again when the policy masks a column of its
  table since, so the masked column leaves the mirror and the sync engine's role can't read it; `authz.sync_verify()`
  says false, and `authz.lint()` reports an error, while a mirror holds a masked column.
- The sync index, a preview: `rowstile apply` changes a PowerSync mirror in place when its table's columns changed
  since (a column added, dropped, or of another type), so the `powersync` publication keeps it; before, apply said
  `unchanged`, and `rowstile reapply` made the mirror again out of the publication. `authz.lint()` warns of such a
  mirror. Apply also makes again a mirror, or the table of what waits after commit, that was dropped since (the
  table's writes failed until then), and warns of each publication a readers table made again (its type's key
  changed) is no longer in.
- The sync index, a preview: a `TRUNCATE` of one partition of a mirrored table, or of a table that inherits from
  it, takes the rows stored there out of the PowerSync mirror, and the index works out the type's readers again.
  Before, the mirror kept them, and PowerSync kept syncing rows the app had deleted.
- The sync index, a preview: in READ COMMITTED, writers whose work meets no longer end in a deadlock (40P01) at
  commit. Three writers could: two waiting for a third, then each reaching what the other held once it committed.
  A lock row the work needs below one it holds is now taken only if nobody holds it; else the work lets go of them
  all and takes them again in order.
- The sync index, a preview: applying refuses a superuser as the sync role saying so (AZ808), not that it is a
  member of the role applying the policy; `authz.lint()` reports a sync role made a superuser since once, not as
  a member of the app role that owns every governed table. Lint still reports another role's privileges on
  `authz_sync` while the sync role is gone (renamed or dropped since).
- A condition that calls a function by its three-part name (`mydb.app.f(id)`), or a function named `filter`,
  `within`, `over` or `is`, is read as calling the app's code, as one written `app.f(id)` is: it runs with the
  policy's rights wherever it is checked, the change feed watches every column of its row, and the sync index
  refuses it (AZ806).
- A condition that limits inheritance can't read who asks or the session through `pg_has_role()`,
  `has_table_privilege()` and the other `has_*_privilege()`, `row_security_active()`, `inet_client_addr()` and
  the other `inet_*` functions, `current_schemas()`, `pg_my_temp_schema()`, `pg_trigger_depth()`, `nextval()`,
  `currval()` or `lastval()`: compiling refuses it (AZ305), in a condition that reads another table too, where
  applying can't ask Postgres. A synced permission that reads them is refused (AZ805).
- `[review] snapshot`, the `[clients]` paths and `[migrations] dir` in `rowstile.toml` stay in the git repository
  it is in (the first folder up with a `.git`), or in its folder when it is in none: `rowstile snapshot` (with or
  without `--check`), `rowstile client`, `rowstile dev` and `rowstile migrate` refuse a path outside it, or a link
  out of it, and name it (exit 2). A monorepo's `../frontend/src/authz.ts` still works. `--out` and `--dir` are
  still the caller's.
- Each view the compiler makes for a relation or a permission has a name of its own: a relation's view of its
  sources other than columns is now `doc__r:ext`, apart from the view of an arrow to a permission named `ext`
  (`r.ext`, `doc__r__ext`), and an arrow followed to some of its types joins them with `__` (`__on_a__b`). The
  compiler fails rather than give one name to two views.
- The sync index, a preview: a share that starts or ends while a writer's transaction is open is worked out again
  by the first `authz.sync_tick()` after that transaction commits, even when a tick ran meanwhile. Before, the index
  kept what the writer worked out (a reader whose share had ended, or none for one that had begun) until something
  else changed that object. The index keeps each object's next share start or end in `authz_sync.due`; applying
  works the index out once again to fill it.
- A caveat that calls a function or an operator of the app's runs with the policy's rights wherever its share
  is checked, as a condition does: a select on the table and its masked view say what `authz.can` and
  `authz.list` say.
- The Elixir SDK: `Rowstile.transact` inside a transaction it didn't begin (a `Repo.transaction` of the app's, a
  Postgrex transaction's connection) raises a `RuntimeError` before anything is sent, as the Python and PHP SDKs
  do, instead of signing that transaction in. `Rowstile.acting_as` says, in its docs, that inside a `transact` the
  statements still run as that transaction's principal.
- The Go SDK: `rowstile.LoginKey(ctx, tx, key)` and `rowstile.LoginJWT` sign a request in with an API key or a
  token inside `Tx`, and `Tx` follows whom the transaction is signed in as from then on: a nested `Tx` for the
  key's principal is a savepoint, and anyone else's is refused. A login made with SQL inside `Tx` left `Tx`
  answering for the principal it began with ([Go](docs/stacks/go.md)).
- The .NET SDK: an EF Core context on a connection where `BeginSignedInAsync` began a transaction, not brought to
  it with `UseTransaction`, no longer signs that transaction in again as whoever the code acts for (Npgsql runs the
  context's commands in it). Its work runs there as it is while the code acts for the transaction's principal, and
  is refused for anyone else with an `InvalidOperationException`, before anything is sent. In a `TransactionScope`
  the connection takes part in, the context's work is refused, as that transaction's sign-in can't be known
  ([ASP.NET Core and EF Core](docs/stacks/aspnetcore.md)).
- Every SDK's test helper keeps the copy's name within Postgres's 63 bytes: a longer one is shortened to its first
  54 bytes (fewer, not to cut a character in two), `_`, and the first 8 hex digits of the SHA-256 of the whole name.
  Postgres cut it before, so a long name could stand for the original, which the helper then dropped, or for
  another worker's copy.
- The Go SDK's `rowstiletest.PerPackage` says so of a URL that doesn't parse, the app role's too, instead of
  failing on it or leaving the app role's URL out.
- The Rust SDK's `per_binary` names the copy in an app role's URL that names no database, and reads a name the URL
  percent-encodes; the Java SDK's `WorkerDatabase.copy` reads it too, and writes the copy's so.
- The Elixir SDK's `database_per_partition` connects with SSL when the URL's `sslmode` asks for it, and the PHP
  SDK's `Databases` pass the URL's settings (`?sslmode=require`) to libpq.
- The Python SDK's `database_per_worker` keeps a URL whose host is in its settings (`postgresql:///app?host=...`)
  as it is written.
- The change feed is in the order of transactions: `authz.changes_since(pos)` gives the entries after the one at
  `pos`, and only those of transactions older than every one still open, so a reader that goes on from the last
  entry it read hears of every entry, even one whose transaction ended after a later one's. The newest entries show
  up once the transactions before them end. `authz.changes_position()` says where the feed is, for a reader that
  starts; a position no entry has gets AZ712, as one trimmed does. `authz.trim_changes()` removes the oldest
  entries in that order.
- `rowstile apply` computes an inheritance table again, instead of keeping it, when its table or link table has
  other tables under it than at the last apply: a partition attached, detached, made or dropped, or a table that
  inherits made or dropped. The rows such a change brings or takes away, which no trigger saw, are then in the
  table, and an apply of the same policy no longer answers `unchanged` after a partition is detached. The
  migrations `rowstile migrate` writes do the same for each inheritance table they keep.
- `authz.explain` for another user (its fourth argument) says only what the one asking may see: its walk stops at an
  object or a team they can't see, as it does when they ask for themselves, and a share's maker, end, start and
  caveat show only where they may list that object's shares (`authz.list_shares`). It says `shared with them` and
  `they are member there` of that user, not `you`.
- `authz.set_role_permissions` refuses to add a permission the caller doesn't hold on each object the role is given
  on, as `authz.share` refuses to give the role there (AZ705): "you cannot give role reviewer on folder 2: you do
  not hold archive", or "on a folder you cannot see" for one they can't see. Taking a permission out still needs
  only `manage_roles`, and a role given to nobody may still be changed freely. A share of the role made meanwhile
  waits for the change, and weighs what the role gives then.
- `authz.break_glass` refuses, naming the share (AZ717), when the caller holds a share of that relation that starts
  later or holds only while a caveat does, instead of replacing it with one that held from now, without the caveat,
  until that share's end. The emergency access ends when its time does; a share that lets the caller in now is left
  as it is.
- Each migration `rowstile migrate` writes turns row-level security on for the partitions of each table with
  rules, and the tables that inherit from one, as each apply does: a partition made or attached since is read
  and written through its table from then on, also when the migration doesn't change that table's rules.
- `TRUNCATE ONLY` on a type's table that other tables inherit from keeps the shares, API keys and pending access
  requests of the rows stored in those tables. Before, it removed them all, as emptying the whole table does.
- `TRUNCATE` run directly on a partition of a watched table, or on a table that inherits from one, removes the
  shares, API keys and pending access requests of the rows it empties, and rebuilds the inheritance trees they
  are in. Before, it ran none of those triggers: the shares stayed until the next apply, a row made later with one
  of the ids got them, and a tree kept rows under a parent that was gone.
- `authz.lint()` counts a privilege on one column as it counts one on the table: it reports a membership table
  without rules that the app role may insert into or update one column of, a partition it may use that way, a
  view that runs with its owner's rights of which it may read one column, and the notes that go with them.
  `authz.connection_check()` reports a login that is a member of a table's owner without inheriting its rights:
  it may `SET ROLE` to the owner.
- `authz.lint()` counts a privilege on one column as it counts one on the table: it reports a membership table
  without rules that the app role may insert into or update one column of, a partition it may use that way, a
  view that runs with its owner's rights of which it may read one column, and the notes that go with them.
  `authz.connection_check()` reports a login that is a member of a table's owner without inheriting its rights:
  it may `SET ROLE` to the owner. It also reports a login that switched to the app role with `SET ROLE` and owns a
  table with rules, or is a member of its owner: `RESET ROLE` leaves the rules.
- `rowstile fmt` lays out a file that starts with a byte order mark as any other, and leaves the mark out. Before,
  it didn't line up the relations and permissions of the file's first block.
- `rowstile test` runs a test whose name, or an id in quotes on one of its lines, holds a dollar quote's tag such
  as `$authz_tests$`. Before, the tag ended the function the tests are compiled into, and Postgres gave a syntax
  error that named nothing of the policy.
- A test's id in quotes is the text in them, `$` or not: `user 1 can view file '$x'` asks about the file whose id is
  `$x`, where `'$x'` was read as the name `$x`; and `a$b` is that text, where it was refused as naming `$b`. An id
  without quotes that starts with `$` and is no name (`$x$`) is refused with its line (AZ106), where compiling the
  tests failed with a Python error.
- A `$name` in a string or a comment of a test's SQL is text: `given {INSERT ... VALUES (9001, 'Ann $smith')}`
  was refused ("$smith is not named yet", AZ501), or had the name's value put inside the string.
- A test file holding a `sync` line, a masked view (`rules app.files view ...`) or a `cascade from` line is
  refused (AZ106), as one holding a type is: a test file holds only named tests. Before, those lines did
  nothing, and nothing said so.
- A string, a quoted name or a dollar quote in a named test's statement (`given {...}`, `as ... {...}`) that goes
  over several lines holds them as written: its line breaks, its spaces and a `--` in it. Before, its lines were
  joined by a space. `rowstile fmt` leaves those lines as written. In a condition elsewhere, such a quote is
  refused with its line (AZ114), where its text was changed the same way.
- An included file that is there and can't be read says why, in the editor and in the suites' compiler as in
  `rowstile check`: it isn't UTF-8, say. Before, the editor and `compile_policy.py` said they couldn't find it.
  `parse_policy` called with neither a path nor the files reads no included file from the current folder.
- A mistake in an included file whose name has a space (`include "my roles.authz"`) is shown where it is: on that
  file and its words in the editor, with its line in `rowstile dev`, with its file and line in the MCP server's
  `check`, in the review and in the playground. Before, the editor put it on the policy's first line, and the
  others lost its place.
- `rowstile apply` remakes a trigger the policy made that is gone when a write rule's condition reads a column named
  `begin`, instead of saying `unchanged`: reading the compiled SQL back, a `begin` in parentheses no longer opens a
  block, as psql reads it. Migrations for Drizzle Kit keep one statement between breakpoints there too.
- A migration that removes an inheritance tree drops the tree's index by its schema (`authz_int`), not by its
  name alone on the search path, where an index of the app's with that name would have gone instead. The lock
  file names those indexes with their schema from the next migration on; one written before needs no migration.
- A migration of a policy whose text ends in `$authz_policy` (a comment, with no newline after it) runs: the quote it
  records the text in no longer ends early.
- `authz.create_api_key` and `authz.list_api_keys` refuse a principal type given without its id (AZ710), instead of
  taking it for the caller's own keys, and `authz.create_api_key` refuses a key with no name or a blank one (AZ710),
  instead of Postgres's own not-null error.
- `authz.explain` for another user names them as the rest of the API does (`user 5`, asked as `'05'`), and
  `authz.sync_members` records the group's id in the audit trail as its shares hold it (`10`, synced as `'010'`).
- The signature `authz.act_as`, the logins and `authz.view_as` put in `authz.session` signs the settings as a list
  that can be read only one way. Before, they were joined with a separator a user id or a token's subject could
  hold, so two different settings could sign alike.
- `rowstile review` reads a policy with sync lines (`sync role`, `sync app.files : view`, `sync after commit`) and
  shows each one that changed under Meaning, instead of stopping with an error.
- `rowstile review` flags under Risk a sync line added, one that finds its rows' readers by another permission
  (`: view` to `: edit`), or one mirrored now: the sync engine is given rows, and who may read them, it wasn't.
- `rowstile review` reads a backslash in an `E'...'` string as escaping the quote after it, so a change to the text
  after it is a change, not spacing. A condition it can't read (a subquery), respaced outside its quotes, is the
  same condition in its small worlds: a permission turned round and respaced is no longer said to widen.
- `rowstile prove`, `rowstile review` and `rowstile why` read `{user = 'alice'}`, `{current_date is null}` and
  conditions on SQL's other such words as the database does: the role, the session or the clock, not a column of
  the row (`{this.user = 'alice'}` and `{"user" = 'alice'}` still name one).
- `rowstile review`'s listed small worlds keep the rows of a type whose `where` reads a relation's column
  (`where {owner_id is not null}`): they read it from the row's link, where before no such row was ever kept and
  the type was never tried.
- `rowstile review` and `rowstile prove` give each value to the other columns a condition reads beside a
  relation's column (`{owner_id = authz.uid() and not locked}`), in the listed worlds and in the corners, so a
  change behind a long `and` in such a condition shows.
- `rowstile review` and `rowstile prove` try, beside a number a condition compares a column with in order, the
  numbers halfway to one less and one more: a numeric column holds 1.5, where `{level > 1}` and `{level >= 2}`
  differ. A whole number past 8,388,607 so compared is left to the database (a real column rounds the half).
- `rowstile review` and `rowstile prove` give their small worlds a row whose id is one a condition compares a
  relation's column with (`{owner_id <> 7}`: a user 7; `{parent_id = 0}`: a folder 0), and the ids either side of
  one compared in order. Such a condition held on every row or on none there, so the review called a change that
  lets everyone edit user 7's folders unchanged, and prove missed the row that breaks an invariant.
- `rowstile help` says what each code refuses today: AZ607's page tells each migration tool how to record a
  migration the database holds already, AZ203's no longer names `shared by` and scopes (AZ207, AZ404),
  AZ107's names `roles`, and AZ208's message and page name the same uses: a permission, a rule, an invariant,
  a group or a roles line's `from`.
- `authz.can`, `authz.list`, `authz.perms` and `authz.perms_of` answer for the rows the user may select: on a table
  with a select rule, a row its rule doesn't let them select reads as a missing one (false, left out of the list,
  no permissions). A permission made of conditions on the row, such as the deny the docs teach (`can hidden =
  {hidden} or parent.hidden`), is held by everyone on the rows it marks, and these answers named those rows.
  A table without a select rule answers as before.
- `rowstile diff` waits for an apply, push or remove running at once, as they wait for each other, instead of the
  two meeting in the middle and one stopping with "deadlock detected". The docs now say that it holds the app's
  tables locked while it runs: run it on a copy or a staging database, not on production at its busiest.
- A migration run a statement at a time (`psql -f` without `-1`), refused (AZ615) with its session made
  read-only, puts the session's setting back in its last statement: a pooler's connection doesn't go on to the next
  client read-only.
- The second of two migrations, which swaps in an inheritance table built beside the one in use, computes the table
  again when the change feed was trimmed meanwhile of the entries of a transaction still open when the first one
  ran. Before, it could miss what that transaction changed. `authz.trim_changes()` records the transaction its trim
  ended at (`changes_trimmed_txid` in `authz.settings`).
- A relation whose two `shared` lines name the same subject with another `shared by` permission or another `shared
  if` condition is refused when compiling, with its line (AZ212). Such a policy failed to apply with `duplicate key
  value violates unique constraint "shared_relations_pkey"` when the permissions differed, and otherwise kept only
  the first line's `shared if`.
- A share with `anyone` is stored with the id `*`, whatever id `authz.share` was given: sharing with `''` and with
  `'*'` makes one share, `authz.unshare` with either id removes it, and `authz.who` counts one made with `''`.
  Applying gives the shares with anyone stored before the id `*`, two of one share kept once.
- Applying after a type's key changed type (text to bigint, say) is refused while shares of rows gone before name
  ids the new key can't read, with the line of the type and how many (AZ627, whose page gives the statement that
  deletes them). It failed with `invalid input syntax for type bigint`, and nothing said which shares or what to
  do. Applying right after deleting them, while a transaction that began before is still open, is refused too, and
  says to apply again once it ends: Postgres builds the index from the rows that transaction still sees.
- A share with `anyone` is stored with the id `*` and no relation, whatever `authz.share` was given: sharing with
  `''` and with `'*'` makes one share, `authz.unshare` with any id removes it (also once the policy no longer
  shares with anyone), and `authz.who` counts one made with `''`. Applying gives the shares with anyone stored
  before the id `*` and no relation, two of one share kept once.
- `rowstile review` reads an included file's name that holds spaces: a mistake's line there (`--json`:
  `base_mistake.line`), and each flag's annotation, on that file and line. `--annotations` escapes the `%`, `:` and
  `,` of a path, as GitHub reads them. Deploy names a quoted table with a space in its name whole, and counts an
  app schema whose name starts with `authz` as the app's. The comment's table escapes a `|` in every cell, an
  invariant's own text too, and a counterexample doubles a quote in a text, as SQL writes it.
- The world `rowstile review` and `rowstile prove` show a difference or a counterexample in leaves out the rows
  that play no part, as it does links and values: one found among 2 users and 4 folders shows the user and the
  folder it is about, not all six.
- `rowstile review` lists 12,000 small worlds at most (60 for each drawn one), even before it has listed every
  world with one link: rows whose conditions give many answers made that many grow fourfold with each condition,
  and a review run for minutes. It then says how far it got ("with no link, and some with one").
- `rowstile review` lists the small worlds where a column compared with `authz.uid()` names a user other than
  the one its row links to (two folders, each made by the other's owner): it took them for the same world with
  the users renamed, which changes whose id the column holds.
- `rowstile init` beside a `rowstile.toml` there already, in its folder or above, that names another policy says
  that no command reads the draft until it does, and the note in `AGENTS.md` names the policy and the tests
  `rowstile.toml` names. Before, it named the draft's.
- An `UPDATE` of `authz.shares` made by hand is recorded with what the share was (`detail`'s `was`: its object,
  relation, subject and times), and announces the object it left also when only its type changed. An `UPDATE` of
  `authz.role_permissions` is recorded (the permission removed, the one added) and announces the objects the role
  is given on. Before, neither was recorded or announced.
- Deleting a row finds the pending access requests and the API keys that name it by index (`authz.requests` has
  indexes of its pending requests, by object and by requester, and `authz.api_keys` one by principal): it no longer
  reads every request ever decided.
- `authz.announce_timed_shares()` keeps each object's next share start or end (`authz.shares_due`, which each
  write of a share puts in) instead of the time of its last run: a clock set back no longer hides the shares that
  end or begin after it until the clock is past that time again. A run waits for a writer adding a share to one of
  the objects it announces, and reads the shares as it left them.
- A `TRUNCATE` run directly on a partition of a watched table, or on a table that inherits from one, is in the audit
  trail, one line naming that table, and the change feed announces every object of its type. A `TRUNCATE` of the
  table above is still one line, naming it. Before, neither heard of the one below.
- A policy with a permission or relation named `tree`, or `tree_` and more (`tree_links`), applies: the closure
  table that an inheritance makes takes another name (`folder__parent__tree2`) where the view of an arrow to that
  name would have had the table's.
- `rowstile migrate` names a file of the migration tool's it can't read and exits 2, where it printed a traceback:
  a Drizzle Kit journal or snapshot that isn't JSON (a merge's conflict markers left in it), a journal entry without
  its `idx` or `tag`, a Django migration that isn't Python, and any of the tool's files, or the lock file, that
  isn't UTF-8. A Drizzle Kit snapshot it can't read leaves no migration file behind.
- The command refuses an option it doesn't take in last place on a line that has `sql` as a value
  (`rowstile migrate --tool sql --check --bogus`): it left the last word out, as it does for `rowstile sql`'s
  statement. A number option given digits of another script (`--worlds ²`) is a usage mistake (exit 2), not a
  traceback.
- `rowstile.toml` refuses a `[migrations] write_after` below 0, which made `rowstile dev` write the migration at
  every save instead of once you stop editing.
- The command run from the source (`core/cli/rowstile`) on a Python older than 3.11 says it needs 3.11 or newer,
  and exits 2, where it stopped with a traceback.
- Ctrl-C stops any command with `stopped` and exit 130: one that reads no database (a long `rowstile prove`,
  `review`, `migrate`), or one still connecting, printed a traceback, as did `rowstile dev` stopped in its first
  pass. `rowstile dev` ends with 0 on Ctrl-C whenever it comes, as it did once watching; `dev --once` with 130.
- The command signs in with a SCRAM password that mixes right-to-left letters (Hebrew, Arabic) with others, or that
  is made only of characters SCRAM drops, as psql does. It prepared such a password other than Postgres had, and
  the server refused it.
- A `#`, a `?` or a `[` in a URL's password is the password's, as libpq reads it. Before, the command refused
  it, or with digits before it connected to the user's name as a host (`postgresql://u:2024#x@h/db`). A message
  about the connection string no longer repeats a piece of a password that wasn't quoted or escaped: a word after
  the password that looked like a setting (`password=my secret=x`), or what came before a `/` in a URL's password.
- A URL's parameter a letter away from a libpq setting (`?sslmod=require`, `?chanel_binding=require`) is refused,
  as a typo, naming the setting meant. Before, it was left alone as an ORM's own, and the command connected
  without what it asked for. An ORM's parameters (`?schema=`, `?pgbouncer=`) are still left alone.
- Studio's grid, on a partitioned table or one that other tables inherit from, marked a row visible when the person
  could see another row stored at the same place in another partition or table. It now tells the tables apart.
- Studio's grid shows a table's columns in the table's order (it put short names first): the first eight, any
  masked column after them, and the names of the others. It counts a table's rows up to 10,000, and says "more
  than 10,000" past that: each page of a big table no longer reads all of it twice.
- Studio's "Make a test" copies json values as the row holds them: a string, a number, a boolean or null in a json
  column made a test that failed. A key that is not a number, text or a uuid is copied as it is, and the test says
  to give the copy a key of its own.
- Studio's access diff no longer says the policy file is the one in force when only an included file changed.

### Upgrading

- A condition with a string, a quoted name or a dollar quote over several lines is refused (AZ114): write it on
  one line, a line break in a string as `E'\n'`.
- A type, a relation or a permission whose name starts or ends with `_` is refused (AZ107), with the line it is
  on: rename it.
- Code that signs one transaction in as two principals now gets AZ716: begin a transaction for each. A test that
  acts for several people in one transaction calls `authz.sign_out()` between them, as the SDKs' test modes do.
  The next apply (or migration) makes the change.
- Sign-ins are signed in a new way. A signature lasts one transaction, so a connection pool keeps none across the
  upgrade. `rowstile apply` and `push` wait for the transactions signed in before them; a migration doesn't, and a
  transaction signed in before it and still open when it commits gets AZ702 on its next statement: retry it.
- A reader of the change feed reads everything again once after the upgrade, then follows from
  `authz.changes_position()` (no longer `max(pos)`, which may stand past an entry still to come).
- A review started more than two weeks ago with the default deadline takes no more decisions: close it, or start
  it again.
- The next apply (or migration) makes `authz.shares_due` from the times the shares have after the last
  `authz.announce_timed_shares()`, and drops the indexes `authz.shares_by_end` and `authz.shares_by_start`, which
  nothing reads any more.

## 0.1.0-beta.3 (2026-11-05)

The sync index, its engines (Electric, Zero, PowerSync) and the new SDKs and stacks are previews: they may
change in any release, and the SDKs not on a registry yet install from the repository.

### Added

- `rowstile dev`'s access lines name, under a permission someone gains, the rules that read it (`read by the
  rules of app.folders: update id, owner_id, org_id, inherit; delete`): whoever gains `share` may then also do what
  those rules let `share` do, such as give a folder away.
- The sync index, a preview (its lines, tables and functions may change in any release): `sync role sync_engine`
  names the sync engine's Postgres role, and `sync app.files : view` (or `sync app.folders`, for the table's select
  rule) keeps, in the schema `authz_sync`, the keys that may read each row and the keys each user holds, current in
  the same transaction as each change, for engines such as Electric to replicate. `authz.sync_tick()` follows shares
  that start or end, and `authz.sync_verify()` compares the index with a rebuild. AZ801 to AZ809 are its mistakes
  ([The sync index](docs/reference/sync.md)).
- The sync index, a preview, keyed by folder: `sync app.files : view by folder` names in each file's readers its
  folder's key (`folder#view:7`), and the index says whose own keys it inherits (`authz_sync.inherits`) and what
  each folder gives itself (`authz_sync.given`), which the engines' filter joins through: a move rewrites no file's
  readers and no key, only what the folders below inherit, and a share on a folder is one row, whatever is below it;
  each user holds their own and their groups' keys, as copied in (AZ810 where a line can't be keyed so). `sync after commit` has a worker,
  `authz.sync_work()`, keep the index after each change commits, so writers don't wait for it;
  `authz.sync_behind()` says how late it is. In the same transaction, writers whose work on the index meets
  nowhere don't wait for each other ([The sync index](docs/reference/sync.md#keyed-by-folder)).
- Electric on the sync index, a preview: `rowstile client electric` (or `[clients] electric`) writes each synced
  table's shape (its filter for the signed-in principal, its key columns, the columns the policy masks), and
  `electricShape()` in `@rowstile/client` is the route in front of Electric that sets it, whatever the client sends:
  401 for nobody, 403 for a session limited by scopes, `Vary` on who asks. Its conformance suite runs Electric
  (`integrations/electric`, [The sync index](docs/reference/sync.md#electric)).
- A stack page for Electric, a preview: the role an administrator makes, the publication the app's migration
  makes, `rowstile client electric`, the route with `electricShape` and `syncPrincipal`, `Vary` and a cache, and
  what can't be done ([Electric](docs/stacks/electric.md)).
- `authz.session_limited()` says whether the signed-in session is limited, by a key's or a token's scopes or by
  viewing as someone, believing the settings only when they are signed, as the rest of rowstile does. The app role
  may call it; `syncPrincipal()` in `@rowstile/client` asks it. A migration
  brings it ([Identity](docs/reference/identity.md)).
- Zero on the sync index, a preview: `rowstile client zero` (or `[clients] zero`) writes the index's tables as Zero
  tables, with their relationships, each synced table's relationship to its readers, the columns the policy masks,
  and each table's filter, which the app's query endpoint adds to the ZQL it gives zero-cache. Its conformance suite
  runs zero-cache 1.11.0 in each of the index's modes, with Zero's query and mutate endpoints signing each request
  in (`integrations/zero`, [The sync index](docs/reference/sync.md#zero), [Zero](docs/stacks/zero.md)).
- PowerSync on the sync index, a preview: `mirrored` on a sync line (`sync app.files : view mirrored`) keeps a copy of
  the table in `authz_sync`, every column but those the policy masks and `readers`, the keys that may read each row,
  kept as the rows and their readers are written; and `rowstile client powersync` (or `[clients] powersync`) writes
  the service's streams, which put each row in a bucket for each key that may read it, its columns read from the
  database. AZ811 refuses a mirrored line keyed by a type, and a table with a column of its own named `readers`. Its
  conformance suite runs the PowerSync service 1.27.0 in both modes a mirror takes (`integrations/powersync`,
  [The sync index](docs/reference/sync.md#powersync), [PowerSync](docs/stacks/powersync.md)).
- `authz.announce_timed_shares()` tells the change feed of the shares that ended (`expires_at`) or began
  (`starts_at`) since it last ran, and of what reads their objects. Run it on a schedule, as `authz.trim_changes()`
  is run ([Operations](docs/operations.md)): no write marks the moment a share ends, so until it runs a reader of
  the feed doesn't hear of it.
- Background jobs in Celery's and RQ's workers, for the Python SDK (preview): `rowstile.job(who)` is a `with` block
  too, for a job that acts for the user its argument names (`Principal.parse`). In either form, the database's
  refusals inside it are raised as `Refused` and `NotFound` (the decorator let the driver's error through before).
  The two keep what they say in their arguments, so pickle and Celery's results give them back whole. The FastAPI
  conformance suite runs them in both workers, on Redis.
- Django, as a preview (it may change in any release): `rowstile[django]` signs every transaction on Django's
  connections in as the request's user (`"rowstile.django"` in `INSTALLED_APPS`, and its middleware), answers
  refusals with 403 and hidden rows with 404, and gives pytest-django a copy of the test database per worker.
  `rowstile migrate` writes Django migrations (`tool = "django"`). [Django](docs/stacks/django.md).
- Preview: the TypeScript SDK on Neon's serverless driver (`@neondatabase/serverless`): `@rowstile/pg` takes its
  `Pool`, over WebSockets, on Node.js and on Next.js's edge runtime, where `checkAtStart` now throws, saying why,
  instead of reaching for `process.exit`. A BullMQ worker and Next's `after()` sign in as `job()` or the request
  say. The Next.js suite checks each, through Neon's `wsproxy` and a real Redis.
- `@rowstile/jest`, a preview: `@rowstile/vitest`'s matchers, `asUser` and a test database per worker, for Jest 30.
  And a conformance suite for a plain Node server, also a preview: Express 5 on pg, Drizzle and postgres.js, with
  Drizzle Kit's migrations and its tests on Jest (`integrations/node`, the Node page).
- A Go SDK, as a preview (`github.com/rowstile/rowstile/sdk/go`, on pgx): transactions signed in, refusals as
  `Refused` and `NotFound`, `net/http` answers, a test database per package; `rowstile client go` writes the
  policy's names for it. Its conformance suite runs a `net/http` app with sqlc's queries and goose's migrations.
- A .NET SDK, as a preview (it may change in any release): `Rowstile`, `Rowstile.EntityFrameworkCore` and
  `Rowstile.AspNetCore` sign each transaction in as the request's user and answer refusals as the other SDKs do,
  `rowstile migrate` writes EF Core migrations (`tool = "efcore"`), and `rowstile client csharp` the policy's names.
- The Ruby SDK for Rails apps, a preview: the `rowstile` gem signs every Active Record transaction in, answers
  refusals 403 and hidden rows 404, refuses to start on a connection that skips row-level security, signs Active
  Job in as a service and copies the test database for each worker. `rowstile migrate` writes Rails migrations
  (`tool = "rails"`), and `rowstile client ruby` and `rbs` the policy's names and their signatures, for Steep.
- A Java SDK, in preview: `dev.rowstile:rowstile` over JDBC, and a Spring Boot starter that signs in every
  transaction Spring begins as the request's user and answers refusals with problem details
  (`docs/stacks/spring.md`). `rowstile client java` writes the policy's names for it. It may change in any release.
- A Kotlin module for the Java SDK, in preview: `dev.rowstile:rowstile-kotlin` signs in transactions from coroutines
  and Exposed's, and its Ktor plugin signs in each request's and answers refusals with problem details
  (`docs/stacks/ktor.md`). It may change in any release.
- A Rust SDK, in preview: the `rowstile` crate signs sqlx and tokio-postgres transactions in, turns refusals into
  typed errors and problem details, and gives Axum an extractor for each request's transaction
  (`docs/stacks/axum.md`). `rowstile migrate` writes sqlx migrations (`tool = "sqlx"`), and `rowstile client rust`
  the policy's names. It may change in any release.
- An Elixir SDK, a preview: the `rowstile` package signs Ecto and Postgrex transactions in, answers refusals
  403 and hidden rows 404 (a Plug, and a Phoenix fallback), refuses to start on a connection that skips row-level
  security, signs Oban jobs in for the user who asked, and copies the test database for each test partition
  (`docs/stacks/phoenix.md`). `rowstile migrate` writes Ecto migrations (`tool = "ecto"`), and `rowstile client
  elixir` the policy's names. It may change in any release.
- A PHP SDK, a preview (it may change in any release): `rowstile/rowstile` signs PDO transactions in, and in Laravel
  every transaction as the request's or the job's principal, answers refusals 403 and hidden rows 404, and copies
  the test database for each worker. `rowstile migrate` writes Laravel migrations (`tool = "laravel"`), and
  `rowstile client php` the policy's names as enums ([Laravel](docs/stacks/laravel.md)).

### Changed

- `rowstile init` takes the policy's app role from the database: the one role the tables are granted to, where it
  wrote `app_user` whatever the app's role was. It says so, and asks to make no role that is there (one that skips
  row-level security: what to change). With several roles granted the tables it names them, and with no tables it
  says the app's migrations come first.
- A refused share or unshare (AZ705) says why, as a refused write does: its DETAIL is what `authz.explain` answers
  the one sharing, for the permission sharing takes (for an object they can't see, what one that isn't there gets).
  The SDKs give it as `why`, which was empty.
- AZ607's title names its most common case: "The database holds the migration already, or isn't where it starts".
- The site's Markdown copy of each page (`/reference/language.md`) and `llms-full.txt` leave out the notes that
  say which check holds each sentence (`<!-- checked: ... -->`), which the pages don't show either.
- A transaction is one principal's, in every SDK. Inside a transaction an SDK signed in already, work for someone
  else, or for no one, is refused before anything is sent for it, with the same words everywhere ("this
  transaction is signed in as user 1 already, and a sign-in lasts the database transaction: service 1's work can't
  run inside it. Run it after, or in a transaction of its own (another connection)", each principal named by its
  type and id, or `nobody`); the transaction goes on as its own principal's. Work for the same principal goes on as
  before. Until now the SDKs differed:
  - Python: `rowstile.psycopg` and `rowstile.asyncpg` blocks took a savepoint and signed back after;
    SQLAlchemy's `install(engine)` kept the outer principal; `rowstile.django` switched statement by statement.
    Each now raises a `RuntimeError`. A psycopg or asyncpg block inside a transaction it didn't begin is refused
    too (who it is signed in as can't be known): psycopg without autocommit opens one at the first statement.
  - TypeScript (`@rowstile/pg`, `/postgres`, `/drizzle`, `/prisma`): opened a second connection (on a pool of one,
    it waited until the pool's timeout). It now throws an `Error`; `@rowstile/client` exports `signedInAlready`.
  - Go: `Tx`/`TxAs` for someone else took a savepoint signed in as them; now an error. So is `Tx` on a transaction
    it didn't begin, or on a `*pgx.Conn` or a `*pgxpool.Conn` in a transaction. To begin one with pgx's options (an
    isolation level, read only), `rowstile.Tx(ctx, rowstile.WithOptions(pool, opts), fn)`.
  - Ruby: switched statement by statement; now a `RuntimeError`. In Rails' transactional tests, each transaction
    the app begins is one principal's, so a test may still act for one person, then another.
  - Django's tests the same: inside the test's transaction, each atomic block the app begins is one principal's.
  - EF Core (`UseRowstile()`) and the Spring Boot starter kept the transaction's principal without a word; now an
    `InvalidOperationException` and an `IllegalStateException`. In Spring, both work that joins the transaction and
    each statement on its connection are checked (a `JdbcClient` call, JPA's, an `Authz` call). The transaction
    managers are handed out as a subclass of their class, so the app may inject them by class
    (`JpaTransactionManager`) or as a `PlatformTransactionManager`; the app's `DataSource` beans the same.
    `Rowstile.signedInAlready(signed, who)` in the Java SDK is the error.
  - Kotlin: `transaction` and `suspendTransaction` refused another principal's inside one of theirs already; now
    each statement in one is checked too (Exposed's, `calls`, and those on `DataSource.transaction`'s connection),
    and inside a blocking `transaction`, `actingFor()` is the principal it signed in as.
  - Rust, Elixir and PHP refuse as they did (Rust's types already keep a transaction to one principal; the other
    two refused already). .NET, Java, Kotlin and Elixir named a principal `1` or `service:1` in the words, and now
    `user 1` and `service 1`; .NET, Java, Python, Ruby and PHP said "the work of code that acts for no one" where
    the others say "nobody's work", which every SDK now says.
- The .NET SDK turns on Npgsql's `Include Error Detail` where it builds the app's connections:
  `AddRowstile(o => o.ConnectionString = ...)`, which now builds the `NpgsqlDataSource`, and a context's
  connection string before `UseRowstile()`. A refused write says why without the app setting it. A data source the
  app builds itself keeps what it was built with.

### Fixed

- `rowstile prove` and the review's refactor check: a relation on the type's own key (`self : user = id`) holds
  on every row's own, in every world they try. They could report a counterexample where it didn't, which no
  database can hold.
- `authz.break_glass` checks the relation's `shared if` for whoever breaks the glass, as `authz.share` does for
  any share, and refuses with the policy's line when it doesn't hold.
- The pages of the SDKs that aren't on a registry yet install them from the repository: the Rails, ASP.NET Core,
  Laravel and Phoenix pages, and the .NET, Rust and Elixir SDKs' own, named packages RubyGems, NuGet, Packagist,
  Hex and crates.io don't have. The README and `llms.txt` list every stack page, and the guide every migration tool.
- The Next.js page: `init` comes after the migrations that make the tables and the app role, not in the install
  lines; the owner's URL is `DATABASE_URL`, the variable `init` writes in `rowstile.toml` and Prisma reads (the
  page used another, so following it gave two); and `prisma migrate resolve --applied` is for the migrations after
  the first, which applies over what `rowstile dev` pushed. The sharing recipe says that the rules reading `share`
  open with it. Paths the docs name as proof are links, and `llms.txt` links the playground on the site.
- The TypeScript SDKs (`@rowstile/pg`, `@rowstile/postgres`, `@rowstile/drizzle`): work that `transaction(fn)`
  (`begin(fn)`) started and that ran after it ended (a promise `fn` didn't await, a timer) still ran on the
  transaction's connection, which by then could be serving another request's transaction, signed in as someone
  else. That work now runs in a transaction of its own, as whoever it acts for.
- `rowstile init` no longer tells a Prisma 7 app to sign in inside Prisma's generated client
  (`src/generated/prisma/client.ts`), which the next `prisma generate` replaces: it skips generated files.
- The Next.js page: its `prisma.config.ts` loads `.env` (`import "dotenv/config"`; Prisma 7 doesn't), and its
  page reads inside `<Suspense>`, which `next build` needs with Cache Components, on in a new `create-next-app`.
  The conformance app now runs with Cache Components.
- The change feed announces what reads a changed object through a relation, and what reads those in turn, with
  the cause `dependent`. It announced only the object itself, so a reader missed objects whose access had
  changed: the files in a moved folder (whose view reads the folder's); the folders and files a team is given,
  shared with or given a custom role on, when a member joins or leaves it (and the teams it sits in); the folders
  of an org whose admins change. Past a thousand objects of a type it says `{*}` for that type. A custom role
  whose permissions change announces the objects it is given on (the cause `role`), and every type's table tells
  the feed of its rows, where before only tables whose columns hold relations did: a change to a column a
  condition reads, or a row of a type only link tables name added or deleted, went unannounced. An update is
  announced only where it changes a row's key, a relation's column or a column the type's conditions name (any
  column, where the compiler can't tell which they read); before, every update of a row whose columns hold
  relations was, a file's renaming too.
  Writes that reach other objects take a little longer: on the docs app, a member leaving a team or a share on a
  folder about half a millisecond more; at most a thousand objects of a type are looked up ([Limits](docs/reference/limits.md)).

### Upgrading

- Work for another principal, or for no one, inside a transaction an SDK signed in already now raises (see
  Changed): run it after that transaction, or in a transaction of its own on another connection.
- An app that reads the change feed, with shares that end or begin at a time (`expires_at`, `starts_at`): schedule
  `authz.announce_timed_shares()`, as `authz.trim_changes()` is, or the feed doesn't hear of those shares
  ([Operations](docs/operations.md)).

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

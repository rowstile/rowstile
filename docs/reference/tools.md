# Tools

| command | what |
|---|---|
| `rowstile init [--schema app] [--users app.users] [--role app_user] [--out db]` | a first policy drafted from your tables and foreign keys, a test file, `rowstile.toml`, and a note for coding agents in `AGENTS.md` (see below); `--role` names the app role the app connects as (without it: the one role the tables are granted to, else `app_user`; run it after the migrations that make the tables and the role) <!-- checked: tests/devx.sh "init takes the app role from the tables' grants: the one role they are granted to"; tests/devx.sh "and with two roles granted them, names both and keeps app_user" -->, `--out` the folder for the policy and its test, below the current one (`rowstile.toml` is written in the current folder) |
| `rowstile dev [p.authz] [--once] [--no-studio] [--studio-port 4983]` | on every save of the policy or its tests: check, show who gains and loses access (for a permission gained, the rules that read it), push, test, write the clients; a mistake stops it before applying. <!-- checked: tests/devx.sh "compiles, applies, tests, writes the client"; tests/devx.sh "says before each push who gains and loses what: rows by table, permissions by type"; tests/devx.sh "and with a permission gained, the rules that read it: what it opens"; tests/devx.sh "a mistake stops it before applying, exit 1" --> With `[migrations]`, it writes the migration once you stop editing. <!-- checked: tests/devx.sh "and writes the migration once the saves stop"; tests/migrations.sh "a save, then quiet: the migration is written, named after what changed" --> Studio runs beside it, and can write, as with `rowstile studio --write` (`--no-studio`: not; on a port another program holds, dev says so and goes on without it) |
| `rowstile studio [--port 4983] [--write]` | Studio, a local web page: the app's tables as anyone, a type at a time, in its key's order (the rows they can't see greyed; a masked column they may not read shown empty, marked `masked`, as they get it), why they hold a permission or not and what would grant it, the policy as a graph, the policy file's access diff on this data, shares and pending requests, and a test from "Ann should see this". <!-- checked: tests/studio_test.py "the rows as bob: some hidden, each with his permissions"; tests/studio_test.py "a type's rows in its key's order, page after page"; tests/studio_test.py "each type's rows with its own permissions"; tests/studio_test.py "a viewer sees the rows, and the masked column as they get it: empty, and named"; tests/studio_test.py "why not, and the changes that might grant it, none tried (read-only)"; tests/studio_test.py "the access diff of a changed file: who gains what, on this data, and nothing applied"; tests/studio_test.py "the shares on an object, as an administrator"; tests/studio_test.py "a pending access request, for how long"; tests/studio_test.py "a test from what should hold: the check on the data there now" --> Read-only unless `--write` (then shares and decisions are made as the person you view as, and what why and the access diff try is rolled back whole); it listens on 127.0.0.1 only, and the address it prints carries a token <!-- checked: tests/studio_test.py "a route that tries no change runs READ ONLY: a write in it is refused"; tests/studio_test.py "why and the access diff, which try changes, may write"; tests/studio_test.py "and nothing any route wrote stays"; tests/studio_test.py "no token: 401 on every route"; tests/studio_test.py "a host that isn't localhost (a DNS name pointed here): 403 on every route"; tests/studio_test.py "no host at all (HTTP/1.0): 403 on every route"; tests/studio_test.py "read-only: no shares made"; tests/studio_test.py "it says it can write, and does"; tests/studio_test.py "a share as the folder's owner, and carol can edit it"; tests/unit_test.py "test_the_url_names_the_address_studio_listens_on"; tests/studio_test.py "the API needs the token" --> A token it doesn't take, one from an earlier start of Studio say (each start makes a new one), is answered 401 with words that say so and which address to open <!-- checked: tests/studio_test.py "a token from an earlier start of Studio: 401, saying Studio was started again and which address to open" --> A change's body is 64 KB at most: a longer one is refused before it is read (413), as any change is when Studio is read-only (403), and one that hasn't come whole after 10 seconds is given up on (408) <!-- checked: tests/studio_test.py "a body over the cap, refused before it is read: 413"; tests/studio_test.py "refused before its body is read: 403, at once"; tests/studio_test.py "a body that doesn't come whole: 408 once the wait is over, and the thread let go" --> Each request connects again: a database it can't reach, or loses while a request waits, is said as the command says it, with 503 <!-- checked: tests/studio_test.py "the page is told it can't connect, as the command says it (503)"; tests/studio_test.py "the server ends Studio's session as a request waits: 503, lost the database in the server's words"; tests/studio_test.py "the connection closed under a request without a word from the server: 503, lost the database"; tests/studio_test.py "and back: the next request connects" --> A share link is turned off with `authz.revoke_link`: Studio refuses to unshare one, and shows no Unshare button for it <!-- checked: tests/studio_test.py "unsharing a share link: refused, saying what turns it off (not a Done that leaves it on)"; tests/studio_page.mjs "a share link: how it is turned off, and no Unshare that would leave it" --> The graph tab loads Mermaid from jsDelivr, a pinned version checked against its hash: without the internet the page shows the graph as text, for any Mermaid viewer <!-- checked: tests/studio_page.mjs "the graph is drawn by Mermaid, from the CDN, its hash checked" --> |
| `rowstile why --as user:42 folder 7 edit` | yes and why; or no, why not, and the smallest changes to the data that would grant it: each is tried in a savepoint and undone, and comes with every other permission it would give them, on any object, who else would gain this one on the folder, and what the people in what it replaces (the owner a column names now) or in a group a deny reads would lose, on any object <!-- checked: tests/studio_test.py "the smallest change first: a share on the folder itself"; tests/studio_test.py "with what else it grants, and the policy line it adds to"; tests/studio_test.py "nothing it tried stays"; tests/studio_test.py "with all it gives: an editor's share higher up gives edit on the folders and the files below too"; tests/studio_test.py "a column: the folder's owner, with the other permissions it gives and whom it takes it from"; tests/studio_test.py "a column that changes hands: all the owner it replaces loses on it"; tests/studio_test.py "a share that a deny reads: what it takes from the others in the team" -->. It offers only changes that change something, and a share only as `authz.share` would make it: its `shared if` judged as someone who may share the object <!-- checked: tests/studio_test.py "the owner who needs the mic: the mic alone"; tests/studio_test.py "that reads who shares is judged as one who may share (ann)"; tests/studio_test.py "on an object nobody may share: not offered, and said" --> |
| `rowstile migrate [p.authz] [--name N] [--check] [--tool T] [--dir D] [--one-phase] [--downgrade]` | the policy's changes since the lock file, as a migration for your tool (no database needed); `--check` exits 1 when a change has no migration (for CI); `--tool` and `--dir` stand in for `[migrations]`'s `tool` and `dir`; `--one-phase` and `--downgrade`: see [Migrations](migrations.md) <!-- checked: tests/migrations.sh "rowstile migrate writes the first migration and db/policy.lock, with no database"; tests/migrations.sh "exit 1, and what changed" --> |
| `rowstile push [p.authz] [--development] [--downgrade]` | a development database brought to the policy by the same migration (never production); `--development` marks a database that already has a policy as one, once <!-- checked: tests/migrations.sh "a database the migrations set up isn't pushed to until someone marks it as a development database"; tests/migrations.sh "marks it, and brings it along with the migration it would write"; tests/migrations.sh "a second change is pushed too" --> A development database you built by running the migrations (to try them) has a policy and no mark: push and `rowstile dev` say so (AZ610) until `rowstile push --development` marks it. <!-- checked: tests/migrations.sh "a database the migrations set up isn't pushed to until someone marks it as a development database" --> Push reads those conditions again too, and refuses one on a dropped column in the same words, whatever the change. <!-- checked: tests/migrations.sh "a where on a column the app dropped since, push of the same policy: refused with its line, not unchanged"; tests/migrations.sh "and the push of another change: refused with its line, nothing pushed" --> |
| `rowstile review [p.authz] [--base main] [--markdown\|--json\|--annotations] [--out FILE] [--db DSN]` | what the change since `--base` does: meaning, access (on a review database), risk, tests, deploy; the pull request comment with `--markdown`, or in a file with `--out FILE`, beside what it prints <!-- checked: tests/review.sh "Meaning: what changed, and what changes through it"; tests/review.sh "Access: who gains what, on the review data"; tests/review.sh "the comment, with its marker and details"; tests/review.sh "the comment in the file, and the annotations printed, from one review" --> |
| `rowstile fmt [--check] [files]` | writes policies and test files one way; `--check` exits 1 when one isn't (for CI) <!-- checked: tests/review.sh "exit 1, and which file"; tests/review.sh "fmt writes it; then" --> |
| `rowstile apply [p.authz] [--force] [--downgrade]` | apply it whole, with the files it includes (read from disk by the command), unless it is in force already (the same text and build, and what it made still there: row-level security on, its policies and triggers). <!-- checked: tests/cli.sh "apply reads the included files from disk"; tests/apply.sh "again: unchanged"; tests/apply.sh "or row-level security turned off on a table with rules"; tests/apply.sh "or a trigger it made on an app table dropped" --> A condition only a function reads (a signing-in type's `where`, a `shared ... if`) that no longer runs, on a column the app dropped since, is refused with its line, as when it was first applied (AZ613), not taken as unchanged. <!-- checked: tests/apply.sh "a column it reads that the app dropped since: apply refuses it with its line, not unchanged"; tests/apply.sh "and a shared if's, the same" --> `--force` applies in any case and computes every inheritance table again, which a plain apply keeps: what to run when `authz.verify()` says false <!-- checked: tests/apply.sh "applies the same text again"; tests/apply.sh "applying again keeps them as they are (unchanged tables are kept)"; tests/apply.sh "and so does apply" --> |
| `rowstile check p.authz` | only report mistakes (the policy's own test lines' too), as `file: line N: message [AZ201]`; exit 1 if there are any <!-- checked: tests/cli.sh "check names the included file and line, exit 1"; tests/cli.sh "check: ok, exit 0"; tests/cli.sh "check, graph and client of a file need no database" --> |
| `rowstile help AZ201`, `rowstile --version` | what a mistake's code means, and the same mistake fixed ([error codes](../errors/README.md); `help errors` lists them); the version, and the Python it runs on |
| `rowstile prove [p.authz] [--worlds N]` | every invariant in many small worlds, with no database: the smallest counterexample (exit 1), or that none was found. <!-- checked: tests/confidence_test.py "an invariant the policy doesn't guarantee: exit 1, and the smallest counterexample"; tests/confidence_test.py "one it does: exit 0" --> A data check (`authz.check_invariants()`) says the data keeps it; prove says whether the policy does <!-- checked: tests/governance.sh "the example data keeps the invariant"; tests/governance.sh "a Globex user owning an Acme folder breaks it"; tests/mcp_test.py "prove: the docs example's counterexample (an owner outside the org may share)" --> `--worlds N` (400) is how many worlds it draws at random. It also tries, at each size, the corners (each condition true on every row, or on none) and the worlds a draw rarely makes (dense links, a chain one link longer than the policy reads), so the count it says is more than N. <!-- checked: tests/confidence_test.py "after every world" --> |
| `rowstile test --coverage` | the tests, then the branches of each permission no passing check makes true, with their lines (`rowstile dev` shows how many on each save). The checks that count are the `can` ones (`user 1 can view folder 3`): a `cannot`, or a statement run `as` someone, covers nothing |
| `rowstile snapshot [--check] [--out FILE]` | who holds what on this database's data, one sorted line per object and permission (in `access.snapshot` beside the policy, or where `[review] snapshot` or `--out` says): on review data, commit it, and a pull request that changes access changes it; `--check` exits 1 when it is out of date |
| `rowstile indexes [--check]` | the lookups the policy makes into the app's tables that no index serves (a type's key among them: each check on one object finds its row by it), why, and the line to add for your migration tool (rowstile doesn't add indexes to your tables: your ORM's diff would see them); `dev` warns at start. For goose and dbmate, which run each migration in a transaction where Postgres builds no index concurrently, the line says to put its `CREATE INDEX CONCURRENTLY` in a migration of its own that starts with `-- +goose NO TRANSACTION` or `-- migrate:up transaction:false`. <!-- checked: tests/confidence_test.py "+goose NO TRANSACTION"; tests/confidence_test.py "migrate:up transaction:false" --> A partitioned table's line has no `CONCURRENTLY`, which Postgres refuses there. <!-- checked: tests/confidence_test.py "a partitioned table: the index to add without CONCURRENTLY" --> A `CREATE INDEX CONCURRENTLY` that fails leaves an unfinished index under the name the line gives, so running the line again fails ("already exists"): `rowstile indexes` names that index first, to drop. <!-- checked: tests/confidence_test.py "... and the line to add says to drop it first" --> |
| `rowstile plans [--as user:1]`, `rowstile bench [--people 10] [--rounds 20]` | each governed table read as someone, timed, with full scans and per-row subplans named; p50 and p95 of reads, lists, checks and updates (undone) as people in the data: `--people` of them (10), `--rounds` times each (20) |
| `rowstile diff p.authz [--users 1,2] [--limit 200]` | who gains and loses what (see [Governance](governance.md)), the first 200 changes listed, or as many as `--limit` says; changes nothing <!-- checked: tests/cli.sh "diff lists who loses what"; tests/cli.sh "diff changed nothing" --> |
| `rowstile lint` | what `authz.lint()` finds, the worst first; exit 1 on an error or a warning <!-- checked: tests/cli.sh "lint where it finds nothing says so, exit 0"; tests/cli.sh "and where it finds a warning, exit 1" --> |
| `rowstile test [tests.authz ...]` | the current policy's tests, these named tests, and the invariants; exit 1 if any fails <!-- checked: tests/cli.sh "test passes and shows each check"; tests/cli.sh "a failing test fails the command, exit 1"; tests/devx.sh "test runs named test files, exit 0" --> |
| `rowstile can\|explain\|perms\|list --as user:42 ...`, `rowstile who [--as user:42] ...` | ask the database as someone |
| `rowstile explain-rule --as user:42 app.files insert --row '{...}'` | why a write is (or would be) refused <!-- checked: tests/docs_test.sh "explain-rule says which rule and what is missing"; tests/cli.sh "explain-rule shows a row a Windows shell took the quotes out of, and how to write it there" --> |
| `rowstile sql --as user:42 "SELECT ..."` | a statement as the app role, signed in as someone; rolled back. A statement that returns no rows says what it did in the server's words: `UPDATE 0, as user:42; rolled back` is a write the rules let change nothing <!-- checked: tests/cli.sh "and says a write changed no row, in the server's words" --> |
| `rowstile lsp` | the language server: errors while typing, hover, go to definition, references, outline, completion (of tables and columns too, with `database` in `rowstile.toml`: not `--db`, `DATABASE_URL` or the `PG*` variables; a database it can't reach yet is tried again some seconds later <!-- checked: tests/lsp_test.py "a database not there at the first completion: its tables some seconds later, in the same server" -->). It reads `rowstile.toml` again when it changes; a mistake in it is shown on it, and the policy is checked without it until it is fixed <!-- checked: tests/lsp_test.py "... the mistake shown on rowstile.toml, on its line, and in a message"; tests/lsp_test.py "rowstile.toml fixed: its mistake cleared at the next message, and its settings taken (the test file checks)" --> |
| `rowstile mcp` | the MCP server, for coding agents (see below) |
| `rowstile graph [p.authz]`, `rowstile client py\|ts\|go\|csharp\|ruby\|rbs\|java\|rust\|elixir\|php [p.authz]` | diagram and typed helpers (`ruby`: the policy's names as constants, for the Ruby SDK; `rbs`: their signatures, for Steep; `java`: the policy's names, as the class `[clients] java`'s path names, `src/main/java/com/example/AuthzNames.java` for `com.example.AuthzNames`; `rust`: the policy's names, a module for the Rust SDK; `elixir`: the policy's names, as the module `[clients] elixir`'s path names, `lib/my_app/authz.ex` for `MyApp.Authz`; `php`: an enum of each type's permissions in the namespace `Authz`, for the PHP SDK, one file for Composer's autoload `files`): of the file, else of the policy `rowstile.toml` names, else of the policy in force; with `--db`, of the policy in force on that database, and `--db` beside a file is refused <!-- checked: tests/cli.sh "reads the policy in force, though rowstile.toml names a file"; tests/cli.sh "and on a graph of a file" --> |
| `rowstile reapply [--force]`, `rowstile remove --yes [--downgrade]` | the policy in force again, after an upgrade (`--force`: and every inheritance table computed again); to take the policy out |
| [`editor/`](../../editor/README.md) | the VS Code and Zed extensions: highlighting (SQL inside `{ }` too) and the language server; a Tree-sitter grammar for Helix and Neovim; other editors start `rowstile lsp` themselves |

`rowstile <command> --help` prints that command's own lines, and `rowstile --help` all of them, on stdout.
A command refuses an option it doesn't take, another command's too, with exit 2, rather than ignore it: `rowstile
check --db URL` says that check reads no database. <!-- checked: tests/cli.sh "an option of another command is refused, exit 2"; tests/cli.sh "on a command that reads no database is refused, saying so" -->
The exit code is for scripts and CI: 0 when the command did what was asked and found nothing wrong; 1 when it
found something or something was refused (a mistake in the policy, a failing test, a lint warning, a `--check` that
finds a difference, a counterexample, an error from the database); 2 when it couldn't do what was asked (a mistake on
the command line or in `rowstile.toml`, a file it can't read or write, a database it can't reach or lost); 130 when
stopped with Ctrl-C. <!-- checked: tests/cli.sh "check names the included file and line, exit 1"; tests/cli.sh "a failing test fails the command, exit 1"; tests/cli.sh "an option of another command is refused, exit 2"; tests/cli.sh "fmt on a file that isn't there says so, exit 2"; tests/cli.sh "a database that doesn't exist: exit 2"; tests/cli.sh "Ctrl-C while sql waits on a statement: stopped at once (exit 130)" -->
`rowstile review` exits 0 whatever it finds: `test` and `migrate --check` are the gates. <!-- checked: tests/review.sh "a base whose policy has a mistake: said first, with its line there and its code, and the policy reviewed as new, exit 0" -->

Commands without a policy file read `rowstile.toml`, found in the current folder or a folder above it:

```toml
policy   = "db/policy.authz"
tests    = ["db/tests/*.authz"]
database = "env:DATABASE_URL"          # a DSN or URL, or env:NAME
[clients]
py = "backend/app/authz_client.py"     # written by rowstile dev (and rowstile client) on every change
ts = "frontend/src/authz.ts"
go = "internal/authz/authz.go"         # the policy's names, for the Go SDK
csharp = "Api/Authz.g.cs"              # the policy's names, for the .NET SDK
ruby = "app/lib/authz.rb"              # the policy's names, for the Ruby SDK
rbs = "sig/authz.rbs"                  # ... and their signatures, for Steep
java = "src/main/java/com/example/AuthzNames.java"   # the policy's names, for the Java SDK
rust = "src/authz.rs"                  # the policy's names, for the Rust SDK
elixir = "lib/my_app/authz.ex"         # the policy's names, for the Elixir SDK (MyApp.Authz)
php = "database/authz.php"             # the policy's names, for the PHP SDK
[migrations]
tool = "alembic"                       # alembic, prisma, drizzle, efcore, rails, ecto, laravel, sql, goose, dbmate,
                                       # flyway, django or sqlx
dir  = "alembic/versions"              # where the tool keeps them (each tool has a default)
lock = "db/policy.lock"                # what the migrations made so far (default: next to the policy)
write_after = 300                      # rowstile dev writes the migration this long after the last save
                                       # (seconds; 0: never, run rowstile migrate yourself)
[review]
snapshot = "db/access.snapshot"        # rowstile snapshot's file (default: access.snapshot next to the policy)
```

The paths in it are from its own folder, wherever the command runs, and so is `migrate --dir`; `--out` (of `init`,
`review` and `snapshot`) is from the current folder. <!-- checked: tests/unit_test.py "test_migrate_dir_is_a_folder_of_rowstile_tomls"; tests/cli.sh "... or where [review] snapshot says, making its folder" -->

The database is `--db` (before or after the command), else `rowstile.toml`'s, else `DATABASE_URL`, else libpq's
`PG*` variables (`PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`, `PGOPTIONS`, `PGSSLMODE`,
`PGSSLROOTCERT`, `PGCHANNELBINDING`, and the others libpq reads; not a password file or a service file). Those nine variables, and the one `database = "env:NAME"`
names, may be in `.env.local` or `.env` beside `rowstile.toml` (in the current folder while there is none), where
Next.js, Prisma and many others keep them: the environment comes first, then `.env.local`, then `.env`, and
`rowstile dev` says when the database came from a file. <!-- checked: tests/cli.sh "the environment comes before both"; tests/cli.sh "rowstile dev says the database came from .env" -->
Nothing else in those files is read, a file that
is a link out of the folder isn't read at all, and with `--db` neither is: the command line named the database. <!-- checked: tests/unit_test.py "test_env_files_are_read_for_the_database_only"; tests/cli.sh "a .env that is a link out of the folder isn't read, and the failure says so"; tests/cli.sh "the files aren't read then" -->
Values are as dotenv writes them: quotes, `#` comments,
`export`, and `${NAME}` filled in. A URL's `?sslmode=`, `?host=`, `?port=` and the like are read, and `?ssl=true`
as `sslmode=require`, as libpq reads it (where the URL has both, the one written last wins); any other value of
`ssl` is refused. <!-- checked: tests/unit_test.py "test_a_urls_ssl_option_as_libpq_reads_it" --> Each of
libpq's settings, in a connection string, a URL or a `PG*` variable, is done as libpq does it, left alone where
that changes neither what is checked nor where the command connects (`application_name`, `keepalives`, `sslsni`
and the like), or refused, naming it: a service, a password file where no password is given, a host address apart
from its name (`hostaddr`), several hosts, client certificates, GSS encryption, OAuth. <!-- checked: tests/unit_test.py "test_each_libpq_setting_is_honoured_left_alone_or_refused"; tests/unit_test.py "test_what_it_cannot_honour_is_refused_not_dropped"; tests/unit_test.py "test_a_url_and_its_options"; tests/unit_test.py "test_prefer_and_allow_as_libpq_tries_them" -->
Three things differ from libpq. The command reads no password file (`~/.pgpass`): give the password in the
connection string or `PGPASSWORD`. Where `connect_timeout` isn't given, it waits 10 seconds for the server (libpq
waits as long as it takes; `connect_timeout=0` does here too). <!-- checked: tests/unit_test.py "test_the_port_and_connect_timeout_as_libpq_reads_them" -->
And the command sends no client certificate: libpq sends `~/.postgresql/postgresql.crt` to a server that asks for
one.
A value in a string of
keywords is quoted as for libpq (`password='it\'s'`). Where nothing names them, the defaults are libpq's: the
system's user, a database named after it, and the server's socket in `/var/run/postgresql` (Debian's and Ubuntu's
folder) or `/tmp` (libpq's own, as Homebrew and Postgres.app build it), whichever has it, or `localhost` on
Windows. <!-- checked: tests/unit_test.py "test_the_defaults_are_libpqs" -->
The warnings the server sends are printed on stderr, as `psql` prints them, those it sends as the session starts
too (a collation version that doesn't match the system's, a setting of the database's it can't take). <!-- checked: tests/cli.sh "a warning the server sends as the session starts is said, on stderr"; tests/cli.sh "and by dev" -->
When the server ends the session in the middle of a command (`pg_terminate_backend`, a server shutting down), the
command says it lost the database and why, in the server's words (`lost the database: terminating connection due
to administrator command`), exit 2. <!-- checked: tests/interrupt.py "it says it lost the database and why (the server's words), exit 2"; tests/interrupt.py "it says it lost the database in the server's words, exit 2" -->

TLS is used when the server has it and required with `sslmode=require`. <!-- checked: tests/unit_test.py "test_tls_as_sslmode_says" -->
The server's certificate is checked
against a root certificate: the one `sslrootcert` names, else `root.crt` in libpq's folder (`~/.postgresql`, or
`%APPDATA%\postgresql` on Windows), with `require` too when there is one, as libpq does; `verify-ca` and
`verify-full` don't go on without one. `sslrootcert=system` checks it against the system's roots and checks its
name, as `verify-full`, and a weaker `sslmode` with it is refused. <!-- checked: tests/unit_test.py "test_the_servers_certificate_as_libpq_checks_it" -->
A certificate `sslcrl`, `sslcrldir` or
`root.crl` lists as revoked is refused. <!-- checked: tests/unit_test.py "test_the_servers_certificate_as_libpq_checks_it"; tests/unit_test.py "test_libpqs_folder" -->
Over TLS the password exchange is bound to the server's certificate when
the server offers it (`channel_binding=prefer`, the default, as in libpq; `disable` never does), so a connection
string from Neon's dashboard works as it is. <!-- checked: tests/unit_test.py "test_scram_is_bound_to_the_tls_channel" -->
With `channel_binding=require`, a server that asks for the password
any other way, or signs the command in without asking, is refused before anything is sent to it. <!-- checked: tests/unit_test.py "test_what_it_refuses_to_send"; tests/unit_test.py "test_each_way_a_server_asks_for_the_password" -->
`require_auth`
says which ways the server may ask, and `target_session_attrs` which session will do, as in libpq. <!-- checked: tests/unit_test.py "test_require_auth_as_libpq_reads_it"; tests/unit_test.py "test_target_session_attrs_as_libpq_checks_it" -->

The files `rowstile.toml` names to be read (the policy, the tests, the lock) are in its folder or
below; a setting it doesn't know, or one of the wrong type, is an error. <!-- checked: tests/cli.sh "a policy outside rowstile.toml's folder is not read"; tests/cli.sh "a misspelt setting is named"; tests/cli.sh "a setting in the wrong table is refused" -->
[Getting started](../getting-started.md) goes through all of it; [the cookbook](../cookbook.md) has tested patterns and
[troubleshooting](../troubleshooting.md) what people run into.

Your stack, step by step: [stacks](../stacks/README.md) (FastAPI, Next.js, other Node and Python apps, and the SQL any other
language sends). To try rowstile with nothing installed, [the playground](../../playground/README.md) runs the compiler and a real Postgres in
the browser (Pyodide and PGlite).

## Coding agents: `AGENTS.md`

`rowstile init` leaves a note for the coding agents that work in the app, in `AGENTS.md` at the project's
root: where the policy and its tests are, the loop after an edit (`check`, `push` on the development
database, `test`, or `dev`), that production takes migrations, that the app connects as the app role and
signs each transaction in, and where the rest is ([llms.txt](../../llms.txt)). Without it an agent sees a
route with no permission check and adds one.

The note sits between `<!-- rowstile:begin -->` and `<!-- rowstile:end -->`. An `AGENTS.md` that is there
keeps its text and gets the section at its end; one that has the markers is left as it is, so the section
is yours to edit, and `init` run again changes nothing. <!-- checked: tests/devx.sh "and an AGENTS.md that is there keeps its text, with the section added"; tests/devx.sh "a second init changes nothing in it"; tests/unit_test.py "test_written_added_and_kept" -->
Delete the section if you don't want it.

## Coding agents: `rowstile mcp`

`rowstile mcp` is a Model Context Protocol server (stdin and stdout) with the command's own tools: `check`,
`prove`, `review`, `test`, `why`, `lint`, and `push` to a development database. <!-- checked: tests/mcp_test.py "each with its input and output"; tests/reference.sh "the MCP server tools.md's settings start lists the tools the page names" -->
Each call runs the command
once, in the folder the agent started it in, so `rowstile.toml` names the policy and the database. <!-- checked: tests/mcp_test.py "check: the policy rowstile.toml names compiles" -->
`check`
also returns the mistake's file and line. <!-- checked: tests/mcp_test.py "a mistake: an answer (not a failed call), with the file, the line and the message" -->
A finding (a mistake, a failing test, a counterexample) is an
answer with `ok: false`; a call that couldn't run (no policy file, no database) is an error. <!-- checked: tests/mcp_test.py "a failing test: an answer (not a failed call), naming the check"; tests/mcp_test.py "a policy file that isn't there: a failed call" -->
So is a call with arguments the tool refuses (one missing, or one that reads as an option): the error is in the
tool's answer (`isError`), with the reason, so the agent sees it and can correct the call. <!-- checked: tests/mcp_test.py "missing arguments: the tool's failed call, naming them, which the agent sees"; tests/mcp_test.py "review's base can't be an option either" -->
The server reads the agent's messages while a call runs: a `ping` is answered at once. <!-- checked: tests/mcp_test.py "a ping while a call runs: answered at once, the call still running" -->
A call the agent cancels (`notifications/cancelled`) gets no answer, and its command is stopped as Ctrl-C stops
it: a cancelled `push` keeps nothing. <!-- checked: tests/mcp_test.py "notifications/cancelled: the call's command stopped (its process ended, the server waited for it)"; tests/mcp_test.py "... and no answer for it: the next answer is the ping's"; tests/mcp_test.py "... no answer for it, and nothing of it kept: the next push applies the change" -->
Stopped (SIGTERM, as an agent's client stops it), the server first stops the commands its calls run, the same
way, and waits for them: none keeps running after it. <!-- checked: tests/mcp_test.py "SIGTERM while a push waits for a lock: its session ended at once, the server after it, nothing left" -->
An agent is given
the command to start it, in its own settings for MCP servers:

```json
{"command": "rowstile", "args": ["mcp"]}
```

Each release publishes the server's entry to the official MCP registry, as `io.github.rowstile/rowstile`, for
clients that find servers there. The entry names the npm package, which brings its own Python. <!-- checked: tests/unit_test.py "test_the_mcp_registrys_entry_names_the_npm_package" -->

`push` is the only tool that changes anything, and it is marked so; production takes migrations. <!-- checked: tests/mcp_test.py "push is the only one that changes anything"; tests/mcp_test.py "push to a database nobody marked: refused" -->

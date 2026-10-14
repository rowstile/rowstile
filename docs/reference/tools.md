# Tools

| command | what |
|---|---|
| `rowstile init [--schema app] [--users app.users]` | a first policy drafted from your tables and foreign keys, a test file, `rowstile.toml`, and a note for coding agents in `AGENTS.md` (see below) |
| `rowstile dev [--once] [--studio-port 4983]` | on every save of the policy or its tests: check, show who gains and loses access, push, test, write the clients; a mistake stops it before applying. <!-- checked: tests/devx.sh "compiles, applies, tests, writes the client"; tests/devx.sh "says before each push who gains and loses what: rows by table, permissions by type"; tests/devx.sh "a mistake stops it before applying, exit 1" --> With `[migrations]`, it writes the migration once you stop editing. <!-- checked: tests/devx.sh "and writes the migration once the saves stop"; tests/migrations.sh "a save, then quiet: the migration is written, named after what changed" --> Studio runs beside it, and can write, as with `rowstile studio --write` (`--no-studio`: not; on a port another program holds, dev says so and goes on without it) |
| `rowstile studio [--port 4983] [--write]` | Studio, a local web page: the app's tables as anyone (the rows they can't see greyed; a masked column they may not read shown empty, marked `masked`, as they get it), why they hold a permission or not and what would grant it, the policy as a graph, the policy file's access diff on this data, shares and pending requests, and a test from "Ann should see this". <!-- checked: tests/studio_test.py "the rows as bob: some hidden, each with his permissions"; tests/studio_test.py "a viewer sees the rows, and the masked column as they get it: empty, and named"; tests/studio_test.py "why not, and the changes that might grant it, none tried (read-only)"; tests/studio_test.py "the access diff of a changed file: who gains what, on this data, and nothing applied"; tests/studio_test.py "the shares and requests"; tests/studio_test.py "a test from what should hold: the check on the data there now" --> Read-only unless `--write` (then shares and decisions are made as the person you view as); it listens on 127.0.0.1 only, and the address it prints carries a token <!-- checked: tests/studio_test.py "read-only: no shares made"; tests/studio_test.py "it says it can write, and does"; tests/studio_test.py "a share as the folder's owner, and carol can edit it"; tests/unit_test.py "test_the_url_names_the_address_studio_listens_on"; tests/studio_test.py "the API needs the token" --> A token it doesn't take, one from an earlier start of Studio say (each start makes a new one), is answered 401 with words that say so and which address to open <!-- checked: tests/studio_test.py "a token from an earlier start of Studio: 401, saying Studio was started again and which address to open" --> A change's body is 64 KB at most: a longer one is refused before it is read (413), as any change is when Studio is read-only (403), and one that hasn't come whole after 10 seconds is given up on (408) <!-- checked: tests/studio_test.py "a body over the cap, refused before it is read: 413"; tests/studio_test.py "refused before its body is read: 403, at once"; tests/studio_test.py "a body that doesn't come whole: 408 once the wait is over, and the thread let go" --> Each request connects again: a database it can't reach, or loses while a request waits, is said as the command says it, with 503 <!-- checked: tests/studio_test.py "the page is told it can't connect, as the command says it (503)"; tests/studio_test.py "the server ends Studio's session as a request waits: 503, lost the database in the server's words"; tests/studio_test.py "the connection closed under a request without a word from the server: 503, lost the database"; tests/studio_test.py "and back: the next request connects" --> |
| `rowstile why --as user:42 folder 7 edit` | yes and why; or no, why not, and the smallest changes to the data that would grant it: each is tried in a savepoint and undone, and comes with every other permission it would give them, on any object, who else would gain this one on the folder, and what the people in what it replaces (the owner a column names now) or in a group a deny reads would lose, on any object <!-- checked: tests/studio_test.py "the smallest change first: a share on the folder itself"; tests/studio_test.py "with what else it grants, and the policy line it adds to"; tests/studio_test.py "nothing it tried stays"; tests/studio_test.py "with all it gives: an editor's share higher up gives edit on the folders and the files below too"; tests/studio_test.py "a column: the folder's owner, with the other permissions it gives and whom it takes it from"; tests/studio_test.py "a column that changes hands: all the owner it replaces loses on it"; tests/studio_test.py "a share that a deny reads: what it takes from the others in the team" -->. It offers only changes that change something, and a share only as `authz.share` would make it: its `shared if` judged as someone who may share the object <!-- checked: tests/studio_test.py "the owner who needs the mic: the mic alone"; tests/studio_test.py "that reads who shares is judged as one who may share (ann)"; tests/studio_test.py "on an object nobody may share: not offered, and said" --> |
| `rowstile migrate [p.authz] [--name N] [--check]` | the policy's changes since the lock file, as a migration for your tool (no database needed); `--check` exits 1 when a change has no migration (for CI) <!-- checked: tests/migrations.sh "rowstile migrate writes the first migration and db/policy.lock, with no database"; tests/migrations.sh "exit 1, and what changed" --> |
| `rowstile push [p.authz] [--development]` | a development database brought to the policy by the same migration (never production); `--development` marks a database that already has a policy as one, once <!-- checked: tests/migrations.sh "a database the migrations set up isn't pushed to until someone marks it as a development database"; tests/migrations.sh "marks it, and brings it along with the migration it would write"; tests/migrations.sh "a second change is pushed too" --> Push reads those conditions again too, and refuses one on a dropped column in the same words, whatever the change. <!-- checked: tests/migrations.sh "a where on a column the app dropped since, push of the same policy: refused with its line, not unchanged"; tests/migrations.sh "and the push of another change: refused with its line, nothing pushed" --> |
| `rowstile review [--base main] [--markdown\|--json\|--annotations] [--db DSN]` | what the change since `--base` does: meaning, access (on a review database), risk, tests, deploy; the pull request comment with `--markdown` <!-- checked: tests/review.sh "Meaning: what changed, and what changes through it"; tests/review.sh "Access: who gains what, on the review data"; tests/review.sh "the comment, with its marker and details" --> |
| `rowstile fmt [--check] [files]` | writes policies and test files one way; `--check` exits 1 when one isn't (for CI) <!-- checked: tests/review.sh "exit 1, and which file"; tests/review.sh "fmt writes it; then" --> |
| `rowstile apply [p.authz] [--force]` | apply it whole, with the files it includes (read from disk by the command), unless it is in force already (the same text and build, and what it made still there: row-level security on, its policies and triggers). <!-- checked: tests/cli.sh "apply reads the included files from disk"; tests/apply.sh "again: unchanged"; tests/apply.sh "or row-level security turned off on a table with rules"; tests/apply.sh "or a trigger it made on an app table dropped" --> A condition only a function reads (a signing-in type's `where`, a `shared ... if`) that no longer runs, on a column the app dropped since, is refused with its line, as when it was first applied (AZ613), not taken as unchanged. <!-- checked: tests/apply.sh "a column it reads that the app dropped since: apply refuses it with its line, not unchanged"; tests/apply.sh "and a shared if's, the same" --> `--force` applies in any case and computes every inheritance table again, which a plain apply keeps: what to run when `authz.verify()` says false <!-- checked: tests/apply.sh "applies the same text again"; tests/apply.sh "applying again keeps them as they are (unchanged tables are kept)"; tests/apply.sh "and so does apply" --> |
| `rowstile check p.authz` | only report mistakes, as `file: line N: message [AZ201]`; exit 1 if there are any <!-- checked: tests/cli.sh "check names the included file and line, exit 1"; tests/cli.sh "check: ok, exit 0"; tests/cli.sh "check, graph and client of a file need no database" --> |
| `rowstile help AZ201` | what a mistake's code means, and the same mistake fixed ([error codes](../errors/README.md); `help errors` lists them) |
| `rowstile prove [p.authz] [--worlds N]` | every invariant in many small worlds, with no database: the smallest counterexample (exit 1), or that none was found. <!-- checked: tests/confidence_test.py "an invariant the policy doesn't guarantee: exit 1, and the smallest counterexample"; tests/confidence_test.py "one it does: exit 0" --> A data check (`authz.check_invariants()`) says the data keeps it; prove says whether the policy does <!-- checked: tests/governance.sh "the example data keeps the invariant"; tests/governance.sh "a Globex user owning an Acme folder breaks it"; tests/mcp_test.py "prove: the docs example's counterexample (an owner outside the org may share)" --> |
| `rowstile test --coverage` | the tests, then the branches of each permission no passing check makes true, with their lines (`rowstile dev` shows how many on each save). The checks that count are the `can` ones (`user 1 can view folder 3`): a `cannot`, or a statement run `as` someone, covers nothing |
| `rowstile snapshot [--check]` | who holds what on this database's data, one sorted line per object and permission (`access.snapshot` beside the policy): on review data, commit it, and a pull request that changes access changes it; `--check` exits 1 when it is out of date |
| `rowstile indexes [--check]` | the lookups the policy makes into the app's tables that no index serves (a type's key among them: each check on one object finds its row by it), why, and the line to add for your migration tool (rowstile doesn't add indexes to your tables: your ORM's diff would see them); `dev` warns at start |
| `rowstile plans [--as user:1]`, `rowstile bench` | each governed table read as someone, timed, with full scans and per-row subplans named; p50 and p95 of reads, lists, checks and updates (undone) as people in the data |
| `rowstile diff p.authz [--users 1,2]` | who gains and loses what (see [Governance](governance.md)); changes nothing <!-- checked: tests/cli.sh "diff lists who loses what"; tests/cli.sh "diff changed nothing" --> |
| `rowstile lint` | what `authz.lint()` finds, the worst first; exit 1 on an error or a warning <!-- checked: tests/cli.sh "lint where it finds nothing says so, exit 0"; tests/cli.sh "and where it finds a warning, exit 1" --> |
| `rowstile test [tests.authz ...]` | the current policy's tests, these named tests, and the invariants; exit 1 if any fails <!-- checked: tests/cli.sh "test passes and shows each check"; tests/cli.sh "a failing test fails the command, exit 1"; tests/devx.sh "test runs named test files, exit 0" --> |
| `rowstile can\|explain\|perms\|list --as user:42 ...`, `rowstile who ...` | ask the database as someone |
| `rowstile explain-rule --as user:42 app.files insert --row '{...}'` | why a write is (or would be) refused <!-- checked: tests/docs_test.sh "explain-rule says which rule and what is missing"; tests/cli.sh "explain-rule shows a row a Windows shell took the quotes out of, and how to write it there" --> |
| `rowstile sql --as user:42 "SELECT ..."` | a statement as the app role, signed in as someone; rolled back |
| `rowstile lsp` | the language server: errors while typing, hover, go to definition, references, outline, completion (of tables and columns too, with `database` in `rowstile.toml`: not `--db`, `DATABASE_URL` or the `PG*` variables) |
| `rowstile mcp` | the MCP server, for coding agents (see below) |
| `rowstile graph [p.authz]`, `rowstile client py\|ts [p.authz]` | diagram and typed helpers |
| `rowstile reapply [--force]`, `rowstile remove --yes` | the policy in force again, after an upgrade (`--force`: and every inheritance table computed again); to take the policy out |
| `core/compile_policy.py p.authz` | without a database: the SQL to apply with psql (one transaction) |
| `core/compile_policy.py p.authz --check` | only report mistakes, as `file: line N: message` <!-- checked: tests/reference.sh "compile_policy.py, as tools.md writes it, only reports a mistake: file, line, message, exit 1" --> |
| `core/compile_policy.py p.authz --tests [tests.authz ...]` | the tests and invariants as SQL (run after applying) |
| `core/compile_policy.py p.authz --diff [--users 1,2]` | who gains and loses what (see [Governance](governance.md)) |
| `core/compile_policy.py p.authz --graph` | a Mermaid diagram of types, relations and permissions |
| `core/compile_policy.py p.authz --client ts\|py` | typed client helpers |
| [`editor/`](../../editor/README.md) | the VS Code and Zed extensions: highlighting (SQL inside `{ }` too) and the language server; a Tree-sitter grammar for Helix and Neovim; other editors start `rowstile lsp` themselves |

`rowstile <command> --help` prints that command's own lines, and `rowstile --help` all of them.

Commands without a policy file read `rowstile.toml`, found in the current folder or a folder above it:

```toml
policy   = "db/policy.authz"
tests    = ["db/tests/*.authz"]
database = "env:DATABASE_URL"          # a DSN or URL, or env:NAME
[clients]
py = "backend/app/authz_client.py"     # written by rowstile dev (and rowstile client) on every change
[migrations]
tool = "alembic"                       # alembic, prisma, drizzle, sql, goose, dbmate or flyway
dir  = "alembic/versions"              # where the tool keeps them (each tool has a default)
```

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
from its name (`hostaddr`), several hosts, client certificates, GSS encryption, OAuth. <!-- checked: tests/unit_test.py "test_each_libpq_setting_is_honoured_left_alone_or_refused"; tests/unit_test.py "test_what_it_cannot_honour_is_refused_not_dropped"; tests/unit_test.py "test_a_url_and_its_options" -->
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
The server reads the agent's messages while a call runs: a `ping` is answered at once. <!-- checked: tests/mcp_test.py "a ping while a call runs: answered at once, the call still running" -->
A call the agent cancels (`notifications/cancelled`) gets no answer, and its command is stopped as Ctrl-C stops
it: a cancelled `push` keeps nothing. <!-- checked: tests/mcp_test.py "notifications/cancelled: the call's command stopped (its process ended, the server waited for it)"; tests/mcp_test.py "... and no answer for it: the next answer is the ping's"; tests/mcp_test.py "... no answer for it, and nothing of it kept: the next push applies the change" -->
An agent is given
the command to start it, in its own settings for MCP servers:

```json
{"command": "rowstile", "args": ["mcp"]}
```

Each release publishes the server's entry to the official MCP registry, as `io.github.rowstile/rowstile`, for
clients that find servers there. The entry names the npm package, which brings its own Python. <!-- checked: tests/unit_test.py "test_the_mcp_registrys_entry_names_the_npm_package" -->

`push` is the only tool that changes anything, and it is marked so; production takes migrations. <!-- checked: tests/mcp_test.py "push is the only one that changes anything"; tests/mcp_test.py "push to a database nobody marked: refused" -->

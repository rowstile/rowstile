# core

rowstile itself: the compiler and the `rowstile` command (Python 3.11 or newer, standard library only), and
their tests. What the language and the command do is in [the reference](../docs/reference/language.md); this
page is for working on them.

| folder | what |
|---|---|
| `authzlib/` | the compiler (Python 3, standard library only); `database.py` is what the command does to a database, `migrate.py` the migrations |
| `cli/` | `rowstile`, the command that compiles and applies, and `pgwire.py`, the small Postgres client it uses |
| `compile_policy.py` | the same compiler without a database: writes the SQL to a file, for the suites and development (installs don't carry it) |
| `example/` | the docs app used throughout: its schema, `docs.authz` and the policy's tests (`docs.test.authz`) |
| `tests/` | every test suite; `run_tests.sh` runs them all, `ci.sh` on every Postgres version |
| `bench/` | the benchmarks: `benchmark.sql` (the docs app, bigger) and the scale benchmark |
| `mutants/` | the mutation sweep: mistakes put into `authzlib` by rule, one at a time, to see that a suite catches each |

From this folder:

    cp example/docs.authz /tmp/docs.authz                    # a copy: migrate writes its lock file beside the policy
    cli/rowstile migrate /tmp/docs.authz --tool sql --dir /tmp/migrations  # the next migration, from the lock file
    cli/rowstile --db "dbname=mydb" push example/docs.authz  # a development database, straight away
    ./run_tests.sh                                           # every test, from scratch (needs Postgres)
    ./ci.sh                                                  # ... on 16, 17 and 18, each in Docker
    ROWSTILE_PART=command ./ci.sh 16                         # one part of the run (unit, policy, command, random)
    ROWSTILE_LANES=1 ./run_tests.sh --quick                  # a part's steps one after the other, not in lanes

## Tested

`./run_tests.sh` runs everything against fresh databases, in about 15 minutes (a few
with `--quick`), as a non-superuser owner of the tables (started as a superuser, it makes one), on
the stock Postgres image. CI runs `--quick` for each push and the whole run each night
(`.github/workflows/nightly.yml`), in parts, each on a machine of its own, side by side (`run_tests.sh` names
them), so a run waits for the longest part and not for their sum. Within a part, the
steps run in three lanes side by side against the same server (`tests/lanes.sh`; `ROWSTILE_LANES` says how many),
each step's output printed whole once it ends, in the order `run_tests.sh` writes them. Each suite's databases,
roles and files have names of its own, and its `trap` drops them however it ends; where two sessions race, the
suite asks the server where each one is (`tests/races.sh`), never a `sleep`:

| suite | what it checks |
|---|---|
| `tests/scenario.sql` | end-to-end checks through RLS as each user, plus the tests in `docs.authz` |
| `tests/multi_scenario.sql` | the second policy (`tests/multi.authz` on `tests/multi_schema.sql`): UUIDs, suspension, mixed-type trees, public and link access, caveats, custom roles, the masked view |
| `tests/difftest.py` | random data and 100 random changes per policy (moves, links, loops, nesting, shares, expiry and start times, id changes, TRUNCATE, multi-statement transactions); after each, `can`, `list`, `explain`, `who`, RLS reads, every policy expression and every column rule's condition (as the owner, and as the app role on the rows it may select) and the masked view are compared for every user (and one of them again with a scope) against a separate reference evaluator; and for one user in turn, `list` in pages of two, which must be the whole list in key order as the database orders the key (its collation's). Six policies (`--gen`: docs, alt, multi, composite, loop, cross: inheritance through two types at once, by columns, link tables and shares, stopped by a condition that reads another table). The questions after a change are asked in up to four sessions side by side, each user's in one session and several users to a session (`DIFFTEST_SESSIONS=1`: in one). |
| `tests/decisions.py` | not a suite: a report, which fails nothing. With `--decisions` (as `run_tests.sh` runs difftest and genpolicy), which parts of each policy decided an answer in their worlds: each part of each permission's and rule's expression, each source of a relation (by the kind of subject it names), each type's where, the shares that don't count (expired, not started, a caveat), each scope, each depth of inheritance and of groups inside groups, a loop in the data. A part decided an answer where, forced the other way in the reference evaluator, some answer the run compares changes. The report names, by line, those never true, never false, never decisive, or decisive one way only: their SQL was never judged there. difftest aims a quarter of its changes at the parts that haven't decided yet: a share that doesn't count where the reference says it would decide had it counted, a chain of links as deep as the part says or a loop of them, the only way down, written through the policy's own sources |
| `tests/unit_test.py` | checks without a database, in about a second: the generated SQL against golden files (`--update` after an intended change), included files, what the command runs, its file reading, the version |
| `tests/features.py` | not a suite: the registry of features. Each `authz.*` function, command and flag, form of the language, error code, SDK export, LSP method, MCP tool and Studio route is in one feature, with its tier, the page that documents it, its fixed checks, the checks that hold it to another answer (the reference evaluator, a rebuild, the policy applied whole) and its hand answers. `Features` in `tests/unit_test.py` reads the surface from the code and fails on an item in no feature, a check gone from its suite, a feature of tier 1 with no check against another answer, or a refusal no check asks for by its words; `--matrix` prints each feature against each suite, and `unit_test.py --update` writes its table into `docs/how-it-is-checked.md` |
| `tests/identity.sh` | scopes, API keys, JWTs (bad signature, expiry, missing expiry, issuer, `alg: none`), view-as, group sync |
| `tests/governance.sh` | audit, feed, requests, break-glass, reviews, invariants, decision log, `--diff`, lint |
| `tests/masks.sh` | masks at apply time, later GRANTs reported by lint and taken back by applying, after renames, in `--diff` |
| `tests/tools_test.py` | the diagram, both clients (every statement prepared against the database; TypeScript type-checked with `tsc --strict` where it is installed), the editor grammar |
| `tests/client_types.py` | the generated TypeScript client under `tsc --strict`, no database: correct calls pass, wrong names don't (CI's `javascript` job) |
| `tests/apply.sh` | what applying does to a database: no extension, only if changed, both scenarios, tests, included files, who may apply, `diff`, `pg_dump` and restore, applying again after an upgrade, removing, and applying as a non-superuser owner |
| `tests/cli.sh` | `rowstile`: every command, included files from disk, errors and exit codes |
| `tests/capitals.sh` | the command over tables named as Prisma names them (`"Folder"`, `"ownerId"`, in `public`): apply, push, lint, indexes, masks, moves, migrations, remove |
| `tests/children.sh` | tables under a governed one (`children.authz`): rows stored in a table that inherits and rows an update puts in another partition, under a rule on a column, a key change (their shares) and the audit; a partition or a table that inherits made after apply (lint, `apply` applies); migrations |
| `tests/migrations.sh` | `rowstile migrate` for each tool, migrations applied in order, out of order and on a new database, `--check`, `push`, a tree built beside while the app writes, `dev` writing the migration |
| `tests/migration_tools.sh` | nightly (`nightly.yml`'s tools job; not in `run_tests.sh`: it starts containers of its own): the migrations for goose, dbmate and Flyway run by each tool itself (their release binaries and image), in an empty folder and in one numbered by hand, then the app's next migration, numbered after rowstile's |
| `tests/upgrade.sh` | the release before this one, from PyPI (`tests/previous_release.py`), makes the docs app's database each way an app may have one (pushed to, applied, set up by its migrations), and the app shares, makes an API key and asks for access; this version then upgrades each as an app does (push, apply, reapply, the next migration from the old lock file): each holds what applying this version on a new database leaves (the columns of the tables kept across applies too), the policy's tests and the scenario pass, and the shares, the key, the request and the audit trail made before are there and work. The release before is one from 0.1.0-beta.1 on (the beta started afresh: no alpha is upgraded from); until one is older than this version, and where PyPI can't be reached, it says so and skips. With a world of data made under the older release (`--world`, every run: `tests/upgrade_world.py`, difftest's docs world, shares in every state, `authz.share`, moves), upgraded by reapply and by a migration: every `authz.can` answer and difftest's questions as on a new database with the same rows, the reference evaluator's answers, the catalog and the inheritance rows. `--every` (nightly, `ROWSTILE_UPGRADES=every`): all of it from every release on PyPI from the beta on. Each release is upgraded with the docs app it was released with (`tests/docs_app.py`: a copy in `tests/docs_apps/` where it differs from `example/`, from its tag; `--sync` writes them) |
| `tests/review.sh` | `rowstile review` in a git repository with a review database: meaning, access, risk, tests, deploy, the comment, JSON and annotations, a refactor found equivalent, the database left as it was; `rowstile fmt` |
| `tests/migrate_test.py` | each kind of policy change, both ways, and what a new version changes alone (a grant, a message of a function, a tree's included): the migration leaves exactly what applying the new policy whole leaves (functions and their privileges, views, triggers, policies, catalogs, the columns of rowstile's types, inheritance rows), with the app writing in between; lines that only move need none, and the database is already what applying whole leaves |
| `tests/interrupt.py` | every run (a sample of the cuts; the full run and `--proofs`: after every statement; `--soak`: other policies' first apply, where the seed says): on the docs app, `rowstile apply` (on a new database and over a policy), `push`, `reapply --force` and both of a migration that builds an inheritance table beside the one in use, each cut after a statement, the command's sent one at a time (the server ends the session, or the connection is closed under it): the command says it lost the database (exit 2), the database is as it was, the app (as the app role, signed in) reads the old policy's answers whole just before the cut and after it, and after some cuts the next run finishes as an uncut one does; between a migration's two, the old policy in force and its inheritance tables exact; the command itself ended by the server while a statement waits for a lock, or stopped by `statement_timeout` |
| `tests/concurrency.sh` | two sessions racing: moves, loops, sharing during a delete |
| `tests/adversarial.sh` | the app role, logged in as its own role, trying to read hidden rows (by id, COPY, leaky functions, prepared statements), reach rowstile's internals (and the catalog of every policy here against the rules, `tests/catalog.sql`), turn row-level security off, change or share what it may not, and learn about hidden objects |
| `tests/docs_test.sh` | `docs/getting-started.md` runs as written and does what the guide says: its SQL and commands, and its Python against the client it writes (`tests/guide_app.py`, over a stand-in for psycopg); the blog post's experiment runs; the policy and the SQL of `README.md` and `site/index.md` apply and run, on `tests/fixtures/landing.sql`, and do what their comments say: `authz.lint()` warns of nothing, a folder moves only under one the user may edit, and only its owner gives it away |
| `tests/fuzz_parser.py` | thousands of mutated policies: each is accepted or refused with a line number, never a crash |
| `tests/fuzz_coverage.py` | nightly only (`nightly.yml`'s fuzz, twenty minutes; Atheris, `tests/fuzz-requirements.txt`): `fuzz_parser.py`'s rule, under a coverage-guided fuzzer over the parser and the compiler, from every policy in the repository |
| `tests/conditions_test.py` | every run (3000; `--soak`: 50000, a new seed each night): conditions made up at random over columns of each kind; each one the reference evaluator reads itself (`authzlib/conditions.py`) must give Postgres's answer on every row, signed in as each user and as nobody |
| `tests/moves.sh` | moves and links of folders with hundreds below them: the stored rows are shifted (rows inside the moved part left alone), loops fall back to recomputing, and the tables match a rebuild after each |
| `tests/policy_errors.py` | policy mistakes (including included files passed as a map), each reported at compile or apply time with its words, its line and its code, and awkward policies that must still work |
| `tests/keep.sh` | applying keeps the inheritance tables whose definition didn't change, and rebuilds the ones that did |
| `tests/principals.sh` | services that sign in as themselves: principal types, their keys and JWTs, `service:*` next to `user:*`, what the audit trail records |
| `tests/sessions.sh` | signed sessions: the app role can't choose its user by setting `authz.user_id`, widen its scopes, or reuse a sign-in in another transaction or connection |
| `tests/devx.sh` | what developers use day to day: named tests with their own data, refusals that say why, `authz.who_among`, drafting a policy, `rowstile dev`, `test`, `init`, `--as` |
| `tests/confidence_test.py` | `rowstile prove`, `test --coverage`, `snapshot`, `indexes`, `plans` and `bench`, on the docs example; the plans of lookups through two-column keys and `(type, id)` pairs; a list on a random policy runs each starting point of a permission once (the calls counted) |
| `tests/lsp_test.py` | the language server over its protocol, as an editor uses it; where there is a database (`createdb` works), also the tables and columns it completes from one |
| `tests/mcp_test.py` | the MCP server over its protocol, as a coding agent's client uses it: each tool in a project folder |
| `tests/studio_test.py` | `rowstile why` and Studio's API: read-only unless `--write`, only for the page that has the token, on localhost; and `rowstile studio` itself: what it prints, and what stops it starting |
| `tests/studio_page.mjs` | Studio's page in Chrome (CI's `studio-page` job: `tests/studio_page.sh` gives it a Postgres of its own; not in `run_tests.sh`, whose containers have no browser): the grid's cells under their headings, "Why?" as anyone and as someone, the graph drawn and a node's detail, the shares and requests as the API sends them, and a policy applied while the page is open |
| `tests/cookbook.sh` | the cookbook's recipes (`docs/cookbook/<name>.md` and its folder): each one's tables and rows load, its policy applies without a warning, its tests pass, its invariants are proved, every line of policy and tests its page shows is in them, the SQL and the commands it shows run as shown, and `rowstile dev` in a copy of the folder applies it and passes its tests |
| `tests/reference.sh` | every code block of `docs/reference/` runs as what it is: a policy compiles with its tests and, on the tables `tests/fixtures/<page>.sql` makes, applies and passes them, SQL runs on the docs app, a refusal shown is the docs app's word for word, `rowstile.toml` makes a project whose `rowstile` lines run in order and whose MCP server lists the tools the page names; a block that can't run says why in a comment before it |
| `tests/hand_answers.sh` | answers worked out by hand from the language's reference, held against the database where only it can give them (a share that expires, a caveat, `shared if`, a write checked before and after, a column rule, a masked column, `this` in a subquery): each `tests/hand/*.authz` is a policy whose named tests hold the answers, applied to a database of its own made from `tests/hand/schema.sql`; `HandAnswers` in `tests/unit_test.py` holds the reference evaluator to the others, and checks every paragraph of the page that says what an answer is has a case |
| `tests/parse_agreement.py` | not run by `run_tests.sh` (it needs the Tree-sitter CLI): the editor job (`editor/test.sh`) runs it on each push, the nightly (`only=grammar`) on more (`editor/test.sh --agree ARGS`). The editors' grammar, written apart from `authzlib/parse.py`, must read each policy as the parser does: the types, each relation's sources, the permissions with their grouping, the rules, scopes, caveats, invariants, and the tests line by line. Each push: every policy in the repository, 200 of genpolicy's and `tests/small.py`'s set up to size 4 (1,379, each as listed and written another way: its names swapped, its parts turned round); each night, the whole set (130,431 policies, and each written another way where that is a policy), in four parts |
| `tests/interleave.py` | every pair of tree writes (and shares) in two sessions, on four trees (the docs app's folders; two types with a condition that reads another table; a partitioned table and tables that inherit; two types linked by their own columns, with a condition that reads their own table), in every order of their steps the server allows (the server, asked, tells a session waiting for a lock from one still running): both in READ COMMITTED on `--quick` and `--short`, each session at each isolation level on the full run and `--proofs`; after each, the inheritance tables match a rebuild, `authz.list` the reference evaluator, and in SERIALIZABLE the rows one transaction after the other |
| `tests/stress.sh` | the full run and `--proofs`: 16 clients writing a folder tree at once at each isolation level; the tables match a rebuild afterwards, and the biggest moves and links on the tree they leave each take under 10 s alone |
| `tests/around.py` | every run (4, in two shares side by side; on the full run the 25 of 1000 seeds in whose worlds every two features of a world meet, `--pairs`, in three shares; `--soak`: 60, a new seed each night): genpolicy's random policies, under the names and with the keys each drew (text keys that are words in the database's own encoding), each in a world drawn at random too: a database with a locale or an encoding of its own (C, LATIN1, Turkish), tables partitioned or with a table that inherits from them (the governed ones, the users', the link tables), a user's row deleted or given another key, the owner's default privileges, conditions that name things without their schema, who connects (the owner switched to the app role, a member of it, one that has to `SET ROLE`) and how each user is signed in (`authz.act_as`, their API key, a JWT) and with which settings, a search path that starts with decoys; then something changed behind the policy's back (a grant, row-level security off, a table made under a governed one). Checked: difftest's checks in that session, real writes as the app role against the rules (updates, deletes, inserts), no share left on a row that is gone, a role the policy doesn't name gets nothing, nobody unsigned gets a row, the privileges are those of a plain database, lint reports what changed and `rowstile apply` puts it right |
| `tests/genpolicy.py` | the full run (23 seeds of 1,000, in which every two of its FEATURES meet) and `--soak` (100, a new seed each night): random policies, each with its tables and data (write rules with conditions that read another table: a subquery, a function called by a quoted name, an operator), checked against the reference evaluator like the fixed ones; a third of them name their tables and columns as an app's own may be (capitals, words SQL reserves, 63 bytes); half of those with text keys make them words (a space, quotes, capitals, accents, a dotted and a dotless i, one a prefix of another, an order each collation has its own of); now and then a policy has a twin with no rule, or no permission, at all; its docstring names the forms it draws, and those it leaves to the fixed policies |
| `tests/rewrites.py` | every run (4 policies; 12 on the full run; `--soak`: 40, a new seed each night): the review's "grants the same", held against the database. A permission or a select rule of genpolicy's random policies is rewritten a few times: in ways that change nothing by what `or`, `and` and `not` mean (parts turned round, a part said twice, `or nobody`, `and anyone`, a part absorbed, an `and` of an `or` written out), and in ways that may (an `and` for an `or`, a part dropped, one relation for another, `and not` added). For each, `rowstile review`'s verdict, which the reference evaluator gives on small made-up worlds, is set beside the database's own diff on the policy's data (`authz.list` and what each select rule shows, for everyone, before and after), as made and after a few random changes. It fails when the review says a rewrite grants the same and the database's answers change, or when a rewrite that changes nothing is given a difference by either. The first difference the review shows for each policy is replayed in a database: its small world made as rows (`small.load_sql`), the user's answer under the policy and under the rewrite must be the review's (what the rows hold is read back: a condition the review can't read holds where they say, and the answer must be the reference evaluator's there) |
| `tests/invariance.py` | every run (genpolicy's seed 2, and `--fixed`: the nine fixed policies' SQL, without a database; 8 policies and the fixed policies' answers on the full run; `--soak`: 20, a new seed each night): changes that must change nothing. Each random policy written another way (its blocks, lines and the operands of each `or` and `and` reordered; spread over included files; laid out again and formatted by `rowstile fmt`) compiles to the same objects as migrations read them, the same SQL but for order, line numbers and the names the compiler numbers as it meets them, and gives the same answers on its data (lists, whole and in pages, checks, `perms_of`, the rows each rule shows, who, `explain_rule`'s verdicts, the invariants); its data with every key of each type renumbered at random gives them too, mapped back |
| `tests/small.py` | every run (every policy up to size 3, and of size 4 with a deny; up to 4 on the full run; `--soak`: up to 6 and the denies of 7, a seventh each night by the day, a week for them all): every policy of the core language up to a size, once each (two spellings of one are one), listed rather than drawn: the user type with or without a `where`, one object type or two, relations from each kind of source (a column, a link table, shares; to users, `user:*`, `anyone`, a link, a group, `parent`, `up`, a pair of columns or a link table naming two types), one or two permissions of up to three parts (`or`, `and`, `and not`, inheritance, a deny) or one of `signed_in`, `anyone` and `nobody` alone. The reference evaluator answers in every world of one and two rows of each type, and some of three; another reading of the policy (its names swapped, its parts turned round) must answer the same. The worlds that tell each part of the policy apart (a part made wrong, a source read wrong, inheritance one step deep) are made as rows, forty policies applied as one, and difftest's checks ask the database. It fails on any difference, and says the smallest world that still fails |

### What the suites run

`core/ci.sh --coverage 16` runs the suites in an image that also has coverage.py (`core/Dockerfile` built with
`COVERAGE=1`). Each Python process they start then measures which lines and branches of `authzlib` and `cli` it
runs, and marks each with the step of `run_tests.sh` that ran it (`ROWSTILE_COVERAGE`; the settings are in
`tests/coverage.ini`). Postgres counts the calls of every function too (`track_functions`), and each database is
asked which of rowstile's functions were called in it before it is dropped (`tests/coverage_functions.sh`, which
`tests/coverage-bin/` puts in front of `createdb` and `dropdb`). `tests/coverage_report.py` reads what they
measured (`.ci/coverage-16/`) and says:

- for each file, how many of its lines and branches the suites run;
- each line and branch that nothing runs;
- what runs of the code that writes the SQL deciding access, but only in steps that never compare the database's
  answers with the reference evaluator (difftest, genpolicy, around): its SQL was made, and never judged (the
  checks that only look for a mistake in the policy, and the messages they make, are set apart);
- each kind of rowstile's functions (`authz_gen."<table>:update:refuse"`, a tree's refresh, `authz.share`) that
  no suite ever calls, as far as Postgres can count: it counts only the calls that return, but keeps a count from
  a function's first call, so a guard whose every call raises is listed apart; a call before a database's last
  apply is lost (applying makes the functions anew), unless the suite measures first, as `tests/governance.sh`,
  `tests/devx.sh` and `tests/principals.sh` do (`bash tests/coverage_functions.sh "$DB"`); a plain SQL function,
  which Postgres may inline, is listed apart too;
- with `core/ci.sh --statements 16` (nightly), each statement and branch of rowstile's PL/pgSQL (schemas `authz`,
  `authz_int`, `authz_gen`) that no suite runs, by kind of function, each `RAISE` first: the coverage image has
  plpgsql_check (PGDG's package) and `--statements` preloads it with its profiler on, which counts every statement
  any session runs, in the server's shared memory.
  `tests/coverage_functions.sh` reads the counts before the drop, as the superuser, with the extension made in a
  schema of its own inside a transaction it rolls back, so no suite ever sees it; `tests/coverage_plpgsql.py` keeps
  them (`plpgsql.jsonl`) and reads each function's source to know which statements begin which arm of an `IF`, a
  `CASE`, a loop or an `EXCEPTION` block (it checks its shares against plpgsql_check's own). What can't run says
  why in `tests/coverage_plpgsql.txt` (`KIND | WORDS | WHY`), and is listed apart;
- with `--diff main`: the lines changed since `main` that nothing runs (exit 1 if there are any).

CI measures on 16 alone: 17 and 18 ran the same lines, branches and functions (compared on 2026-10-10). Code that
only another version runs would need theirs measured again (`--coverage` in `.github/workflows/suites.yml`).

### How many checks each suite passes

A suite can stop checking something and stay green: a glob that matches nothing, a loop over an empty list, a
suite cut short, a test that skips. So `tests/check_counts.txt` says how many checks each suite passes, and
`core/ci.sh` holds every run to it (`tests/check_counts.py`, on the run's log): a suite that passes fewer or more
fails the run, though each of its checks passed, and a count that changes is in the diff, like the golden SQL. After
adding or taking away checks on purpose, write the new count there, or `python3 tests/check_counts.py --write LOG`
with the run's log (`/tmp/rowstile-ci-16.log`). A skipped unit test isn't a passed one: the unit tests' count is
what they pass in `ci.sh`'s container, where those that ask git skip. The random suites (difftest, genpolicy, around,
the invariance of random policies, the conditions, the parser fuzzer, the rewrites, the stress test) check as many
things as their seeds draw, and aren't counted.

### Mistakes put in on purpose

A suite can pass and still check too little. So `mutants/` puts small mistakes into `authzlib`, one at a time, and
runs the suites until one goes red. `mutants/mutants.py` makes them by rule: in the SQL the compiler writes, `AND`
for `OR`, `=` for `<>`, `<` for `<=`, `IS NULL` for `IS NOT NULL`, `EXISTS` for `NOT EXISTS`, a `coalesce`'s
default flipped, a term of a `WHERE` dropped, a `PERFORM`, `SECURITY DEFINER` or `SET search_path` taken out; in the
Python, each comparison turned round, a `not` dropped or added, each `if` forced either way, an item of a list
dropped, a quoting call (`q`, `qt`, `lit`) dropped. Never in an f-string's fields, a docstring, a message or an SQL
comment. Each mutant has an id (`g` and ten hex digits) that stays the same until its own line changes.

`mutants/plan.py` first compiles every policy in the repository before and after each mutant, with no database:
the fixed policies, the cookbook's, the four apps', the docs app's diagram, clients and diffs, and the migrations
`tests/migrate_test.py` checks. A mutant that changes none of them is equivalent for all of them and doesn't run
(`same`); one that breaks a compile is caught there. The others run the suites. Those that called a function whose
SQL changed, or ran the mutated line (CI's coverage run on `main`: `functions.tsv` and coverage.py's contexts),
run first, then the rest; each group the most catches per second first. Each suite's catches and seconds come
from the newest run that kept them (no copy is kept here: it would go stale), and the report names that run. A
catch counts when the suite is red twice, and only if it is green unmutated on the same machine.

It runs on GitHub's runners (`.github/workflows/mutants.yml`), weekly and by hand, never on a push: a job prepares
the queue, up to eight jobs run a share of it each, side by side, and a last one collects the results. Each run
carries over the results of the last one whose mutants' lines are unchanged, and takes the next mutants in an
order spread over operators and files. A mutant no suite catches (a survivor) is listed in
`mutants/survivors.txt`, as `equivalent` (it can't change an answer) or `lead` (the check that would catch it): a
survivor not listed fails the run. The run's summary has the score, what caught what and each survivor's edit;
the artifact `mutants-results` has every result. A run of some mutants only (`only`, `since`, `limit`) with
`resume` other than `latest` holds only its own results: it keeps them as `mutants-results-partial`, which the
next run doesn't start from.

    gh workflow run mutants.yml -f since=<commit>    # the mutants in lines changed since that commit
    gh workflow run mutants.yml -f limit=40          # 40 that need suites, spread over operators and files
    gh workflow run mutants.yml -f only=<id>,<id>    # these mutants
    python3 mutants/sweep.py list --since <commit>   # which mutants those are, here, without running anything

By hand, with Docker: `docker build -t rowstile:16 --build-arg PG_MAJOR=16 -f core/Dockerfile .` from the
repository's root, then from this folder `python3 mutants/sweep.py prepare --out /tmp/m --only <id>`,
`python3 mutants/sweep.py run --prepared /tmp/m --shard 1/1 --out /tmp/m/run` (a Postgres container of its own;
it changes this checkout's `authzlib` and puts it back after each mutant) and `python3 mutants/sweep.py collect
--prepared /tmp/m --shards /tmp/m/run --out /tmp/m/results`.

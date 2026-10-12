# core

rowstile itself: the compiler and the `rowstile` command (Python 3.11 or newer, standard library only), and
their tests. What the language and the command do is in [the reference](../docs/reference/language.md); this
page is for working on them.

| folder | what |
|---|---|
| `authzlib/` | the compiler (Python 3, standard library only); `database.py` is what the command does to a database, `migrate.py` the migrations |
| `cli/` | `rowstile`, the command that compiles and applies, and `pgwire.py`, the small Postgres client it uses |
| `compile_policy.py` | the same compiler without a database: writes the SQL to a file (for development, tests and the editor) |
| `example/` | the docs app used throughout: its schema, `docs.authz` and the policy's tests (`docs.test.authz`) |
| `tests/` | every test suite; `run_tests.sh` runs them all, `ci.sh` on every Postgres version |
| `bench/` | the benchmarks: `benchmark.sql` (the docs app, bigger) and the scale benchmark |

From this folder:

    cli/rowstile migrate example/docs.authz --tool sql       # the next migration, from the lock file
    cli/rowstile --db "dbname=mydb" push example/docs.authz  # a development database, straight away
    ./run_tests.sh                                           # every test, from scratch (needs Postgres)
    ./ci.sh                                                  # ... on 16, 17 and 18, each in Docker
    ROWSTILE_PART=command ./ci.sh 16                         # one part of the run (unit, policy, command, random)
    ROWSTILE_LANES=1 ./run_tests.sh --quick                  # a part's steps one after the other, not in lanes

## Tested

`./run_tests.sh` runs everything against fresh databases, in about 15 minutes (a few
with `--quick`), as a non-superuser owner of the tables (started as a superuser, it makes one), on
the stock Postgres image. CI runs it in parts, each on a machine of its own, side by side
(`run_tests.sh` names them), so a push waits for the longest part and not for their sum. Within a part, the
steps run in three lanes side by side against the same server (`tests/lanes.sh`; `ROWSTILE_LANES` says how many),
each step's output printed whole once it ends, in the order `run_tests.sh` writes them:

| suite | what it checks |
|---|---|
| `tests/scenario.sql` | end-to-end checks through RLS as each user, plus the tests in `docs.authz` |
| `tests/multi_scenario.sql` | the second policy (`tests/multi.authz` on `tests/multi_schema.sql`): UUIDs, suspension, mixed-type trees, public and link access, caveats, custom roles, the masked view |
| `tests/difftest.py` | random data and 100 random changes per policy (moves, links, loops, nesting, shares, expiry and start times, id changes, TRUNCATE, multi-statement transactions); after each, `can`, `list`, `explain`, `who`, RLS reads, every policy expression and every column rule's condition (as the owner, and as the app role on the rows it may select) and the masked view are compared for every user (and one of them again with a scope) against a separate reference evaluator. Six policies (`--gen`: docs, alt, multi, composite, loop, cross: inheritance through two types at once, by columns, link tables and shares, stopped by a condition that reads another table). The questions after a change are asked in up to four sessions side by side, each user's in one session and several users to a session (`DIFFTEST_SESSIONS=1`: in one). |
| `tests/decisions.py` | not a suite: a report, which fails nothing. With `--decisions` (as `run_tests.sh` runs difftest and genpolicy), which parts of each policy decided an answer in their worlds: each part of each permission's and rule's expression, each source of a relation (by the kind of subject it names), each type's where, the shares that don't count (expired, not started, a caveat), each scope, each depth of inheritance and of groups inside groups, a loop in the data. A part decided an answer where, forced the other way in the reference evaluator, some answer the run compares changes. The report names, by line, those never true, never false, never decisive, or decisive one way only: their SQL was never judged there. difftest aims a quarter of its changes at the parts that haven't decided yet: a share that doesn't count where the reference says it would decide had it counted, a chain of links as deep as the part says or a loop of them, the only way down, written through the policy's own sources |
| `tests/unit_test.py` | checks without a database, in about a second: the generated SQL against golden files (`--update` after an intended change), included files, what the command runs, its file reading, the version |
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
| `tests/upgrade.sh` | the release before this one, from PyPI (`tests/previous_release.py`), makes the docs app's database each way an app may have one (pushed to, applied, set up by its migrations), and the app shares, makes an API key and asks for access; this version then upgrades each as an app does (push, apply, reapply, the next migration from the old lock file): each holds what applying this version on a new database leaves (the columns of the tables kept across applies too), the policy's tests and the scenario pass, and the shares, the key, the request and the audit trail made before are there and work. Where PyPI can't be reached it says so and skips |
| `tests/review.sh` | `rowstile review` in a git repository with a review database: meaning, access, risk, tests, deploy, the comment, JSON and annotations, a refactor found equivalent, the database left as it was; `rowstile fmt` |
| `tests/migrate_test.py` | each kind of policy change, both ways: the migration leaves exactly what applying the new policy whole leaves (functions and their privileges, views, triggers, policies, catalogs, inheritance rows), with the app writing in between |
| `tests/concurrency.sh` | two sessions racing: moves, loops, sharing during a delete |
| `tests/adversarial.sh` | the app role, logged in as its own role, trying to read hidden rows (by id, COPY, leaky functions, prepared statements), reach rowstile's internals (and the catalog of every policy here against the rules, `tests/catalog.sql`), turn row-level security off, change or share what it may not, and learn about hidden objects |
| `tests/docs_test.sh` | the SQL of `docs/getting-started.md` runs as written and does what the guide says |
| `tests/fuzz_parser.py` | thousands of mutated policies: each is accepted or refused with a line number, never a crash |
| `tests/conditions_test.py` | every run (3000; `--soak`: 50000, a new seed each night): conditions made up at random over columns of each kind; each one the reference evaluator reads itself (`authzlib/conditions.py`) must give Postgres's answer on every row, signed in as each user and as nobody |
| `tests/moves.sh` | moves and links of folders with hundreds below them: the stored rows are shifted (rows inside the moved part left alone), loops fall back to recomputing, and the tables match a rebuild after each |
| `tests/policy_errors.py` | policy mistakes (including included files passed as a map), each reported at compile or apply time, and awkward policies that must still work |
| `tests/keep.sh` | applying keeps the inheritance tables whose definition didn't change, and rebuilds the ones that did |
| `tests/principals.sh` | services that sign in as themselves: principal types, their keys and JWTs, `service:*` next to `user:*`, what the audit trail records |
| `tests/sessions.sh` | signed sessions: the app role can't choose its user by setting `authz.user_id`, widen its scopes, or reuse a sign-in in another transaction or connection |
| `tests/devx.sh` | what developers use day to day: named tests with their own data, refusals that say why, `authz.who_among`, drafting a policy, `rowstile dev`, `test`, `init`, `--as` |
| `tests/confidence_test.py` | `rowstile prove`, `test --coverage`, `snapshot`, `indexes`, `plans` and `bench`, on the docs example |
| `tests/lsp_test.py` | the language server over its protocol, as an editor uses it; where there is a database (`createdb` works), also the tables and columns it completes from one |
| `tests/mcp_test.py` | the MCP server over its protocol, as a coding agent's client uses it: each tool in a project folder |
| `tests/studio_test.py` | `rowstile why` and Studio's API: read-only unless `--write`, only for the page that has the token, on localhost; and `rowstile studio` itself: what it prints, and what stops it starting |
| `tests/cookbook.sh` | the cookbook's recipes (`docs/cookbook/<name>.md` and its folder): each one's tables and rows load, its policy applies without a warning, its tests pass, its invariants are proved, and every line its page shows is in them |
| `tests/reference.sh` | every code block of `docs/reference/` runs as what it is: a policy compiles with its tests, SQL runs on the docs app, a refusal shown is the docs app's word for word, `rowstile.toml` makes a project whose `rowstile` lines run in order and whose MCP server lists the tools the page names; a block that can't run says why in a comment before it |
| `tests/races.sh` | the full run and `--proofs`: every pair of tree writes raced in two sessions at each isolation level; the inheritance tables match a rebuild after each |
| `tests/stress.sh` | the full run and `--proofs`: 16 clients writing a folder tree at once at each isolation level; the tables match a rebuild afterwards, and the biggest moves and links on the tree they leave each take under 10 s alone |
| `tests/around.py` | every run (4; 16 on the full run; `--soak`: 60, a new seed each night): genpolicy's random policies, under the names and with the keys each drew, each in a world drawn at random too: a database with a locale or an encoding of its own (C, LATIN1, Turkish), tables partitioned or with a table that inherits from them (the governed ones, the users', the link tables), a user's row deleted or given another key, the owner's default privileges, conditions that name things without their schema, who connects (the owner switched to the app role, a member of it, one that has to `SET ROLE`) and with which settings, a search path that starts with decoys; then something changed behind the policy's back (a grant, row-level security off, a table made under a governed one). Checked: difftest's checks in that session, real writes as the app role against the rules, no share left on a row that is gone, a role the policy doesn't name gets nothing, nobody unsigned gets a row, the privileges are those of a plain database, lint reports what changed and `rowstile apply` puts it right |
| `tests/genpolicy.py` | the full run (12) and `--soak` (100, a new seed each night): random policies, each with its tables and data (write rules with conditions that read another table: a subquery, a function called by a quoted name, an operator), checked against the reference evaluator like the fixed ones; a third of them name their tables and columns as an app's own may be (capitals, words SQL reserves, 63 bytes); now and then a policy has a twin with no rule, or no permission, at all |
| `tests/rewrites.py` | every run (4 policies; 12 on the full run; `--soak`: 40, a new seed each night): the review's "grants the same", held against the database. A permission or a select rule of genpolicy's random policies is rewritten a few times: in ways that change nothing by what `or`, `and` and `not` mean (parts turned round, a part said twice, `or nobody`, `and anyone`, a part absorbed, an `and` of an `or` written out), and in ways that may (an `and` for an `or`, a part dropped, one relation for another, `and not` added). For each, `rowstile review`'s verdict, which the reference evaluator gives on small made-up worlds, is set beside the database's own diff on the policy's data (`authz.list` and what each select rule shows, for everyone, before and after), as made and after a few random changes. It fails when the review says a rewrite grants the same and the database's answers change, or when a rewrite that changes nothing is given a difference by either |

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
  apply is lost (applying makes the functions anew), unless the suite measures first, as `tests/governance.sh`
  and `tests/devx.sh` do (`bash tests/coverage_functions.sh "$DB"`); a plain SQL function, which Postgres may
  inline, is listed apart too;
- with `--diff main`: the lines changed since `main` that nothing runs (exit 1 if there are any).

CI measures on 16 alone: 17 and 18 ran the same lines, branches and functions (compared on 2026-10-10). Code that
only another version runs would need theirs measured again (`--coverage` in `.github/workflows/ci.yml`).

### How many checks each suite passes

A suite can stop checking something and stay green: a glob that matches nothing, a loop over an empty list, a
suite cut short. So `tests/check_counts.txt` says how many checks each suite passes, and `core/ci.sh` holds every
run to it (`tests/check_counts.py`, on the run's log): a suite that passes fewer or more fails the run, though
each of its checks passed, and a count that changes is in the diff, like the golden SQL. After adding or taking
away checks on purpose, write the new count there, or `python3 tests/check_counts.py --write LOG` with the run's
log (`rowstile-ci-16.log`, in `/tmp` or where `ROWSTILE_CI_LOGS` says). The random suites (difftest, genpolicy,
around, the conditions, the parser fuzzer, the stress test) check as many things as their seeds draw, and aren't
counted.

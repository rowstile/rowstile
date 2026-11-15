---
paths:
  - "core/**"
---

# core/: the compiler, the command, the suites

What each part of `core/` holds, how its suites run, and the rules the compiler and its SQL keep.

## Layout

- `core/` — rowstile itself: the compiler, the command, their tests (main work happens here)
  - `authzlib/` — compiler, standard library only; `__version__` in `__init__.py` is the version the command
    and the packages carry (`packaging/version.py X.Y.Z` sets it everywhere; `unit_test.py` checks they
    agree). `Compiler` (`assembled.py`; `authzlib.Compiler`, imported when first asked for) is a stack of mixins:
    - `parse.py` — parser (app role, types, relations, perms, rules, scopes, caveats, sync, invariants, tests,
      includes; includes come from a `files` map when given, never from disk)
    - `compiler.py` (Core) — validation, recursion/SCC analysis, per-relation/permission views
    - `trees.py` — closure tables for inheritance + their triggers
    - `output.py` — assembles the final SQL (`compile()`), RLS policies, `can/list/perms`, sharing API, masked views
    - `insight.py` — `who`, `explain`, `list_shares`
    - `identity.py` — scopes, API keys, JWT login, view_as, sync_members, audit helper
    - `governance.py` — audit/feed triggers, requests, break_glass, reviews, invariants, diff (`diff_parts`)
    - `hardening.py` — `authz.lint()`
    - `devtools.py` — graph (Mermaid), clients (py, ts; with `Refused`, `NotFound`, `refusal`, `expect`, `who_among`;
      `ts-sdk`: only the names, for apps on the TypeScript SDK; the names alone for the other SDKs: go, csharp, ruby,
      rbs (their signatures), java, rust, elixir, php; and for the sync engines: electric, zero, powersync)
    - `testing.py` — policy tests: the unnamed section, named tests (`given`, `as user X allowed|refused|sees`;
      `with scope a, b` after who: the line as a key limited to those scopes), invariants,
      compiled into one plpgsql function `pg_temp.authz_policy_tests()` returning a row per check
    - `refusals.py` — refused writes that say why, `authz.explain_rule`, `authz.who_among`
    - `draft.py` — a first policy from the catalog (`rowstile init`)
    - `base.py` — persistent tables (`authz.shares`, `authz.audit`, ...; a new column last, with an
      `ADD COLUMN IF NOT EXISTS` beside it), `authz.ctx`, `GENERATED_FUNCTIONS`
    - `sqlutil.py` — quoting helpers (`q`, `qt`, `lit`, ...), `this.`, and `reads_more` (whether a condition
      reads more than its row: then it runs with the policy's rights)
    - `conditions.py` — simple conditions (`{not archived}`, `{owner_id = authz.uid()}`) read as facts about
      the row, for the reference evaluator; only where the column can't hold two texts the policy compares as one
      value (`alike`), the rest left to the database (`tests/conditions_test.py` asks Postgres the same questions)
    - `connection.py` — the `Db` authzlib works over, and typed readers for the values its rows hold
    - `versions.py` — how a version is written (X.Y.Z, -alpha.N, -beta.N, -rc.N, -dev), its stages' order and
      PyPI's spelling: the one grammar `packaging/version.py`, the downgrade guard, `cli/stack.py` and
      `tests/previous_release.py` read
    - `database.py` — what the command does to a database: apply (only if changed), push, reapply, check, diff,
      test, draft, graph, client, remove, and the migrations; over a `db` with `rows`/`script`/`warn`/`errors`, in
      the caller's transaction (compiles with `transaction=False`: no BEGIN/COMMIT)
    - `statements.py` — the compiled SQL read back as statements (quotes, dollar quotes, BEGIN ATOMIC), and the
      object each one makes
    - `evaluate.py` — the reference evaluator (sets of ids, a least fixpoint, straight from the policy) and small
      worlds made up for two policies at once (`compare`: the review's refactor check; drawn ones, and `Listing`:
      every world of up to 3 rows a type, the fewest links first); difftest uses it
    - `review.py` — `rowstile review`: meaning, access, risk, tests, deploy; markdown, text, JSON,
      annotations
    - `fmt.py` — `rowstile fmt`: one layout, refused if it would change what the policy says
    - `prove.py` — `rowstile prove`: invariants in many small worlds (the reference evaluator), the smallest
      counterexample, shrunk row by row, then link by link
    - `coverage.py` — the branches of each permission no passing check makes true (from `authz.explain`'s
      answers, which the test function returns with `coverage=True`)
    - `errors.py` — each error code's page (title, meaning, the mistake, the fix); `rowstile help AZ201`
    - `perf.py` — the indexes the policy's lookups need (named, never created: they are the app's schema),
      `plans` (EXPLAIN ANALYZE as the app role) and `bench`
    - `grant.py` — `rowstile why` and Studio: the changes to the data (a share, a link row, a column, joining a
      group, the permission on the object above) that would grant a permission, each tried in a savepoint as the
      owner and undone, with what else it grants (a preview: the command's, not the runtime's)
    - `migrate.py` — policy changes as migrations: the compiled policy as objects, the lock file,
      the migration from a lock to a policy (only what changed), trees built beside then swapped in
    - `sync.py` — the sync index (a preview): who may read each synced row, as keys in schema `authz_sync`
      (readers, keys, groups; keyed by a type's inheritance; PowerSync's mirrors), worked out again at commit or,
      with `sync after commit`, by `authz.sync_work()`; `sync_tick`, `sync_verify`, the sync role's grants and lint
  - `cli/` — the command runs on Python 3.11 or newer, standard library only: `rowstile` (`rowstile_cli.py`: compiles, and runs `authzlib.database` over its own connection; reads
    included files and `rowstile.toml` from disk; `dev` watches and runs the loop), `lsp.py` (the
    language server, `rowstile lsp`), `mcp.py` (the MCP server for coding agents, `rowstile mcp`: each tool runs
    the command once; `tests/mcp_test.py`), `init.py` (`rowstile init`), `migrations.py` (a migration's files for
    each tool `TOOLS` names: Alembic, Django, Prisma, Drizzle Kit, Rails, Laravel, Ecto, EF Core, sqlx, goose,
    dbmate, Flyway or plain SQL), `stack.py` (the app's stack, for
    `init`), `studio.py` and `studio/` (Studio: a local web page and its JSON API; read-only transactions unless
    `--write` or `dev`; localhost and a token; `tests/studio_test.py`) and `pgwire.py` (stdlib Postgres client,
    SCRAM, notices, URLs, `script()` for many statements)
  - `compile_policy.py` — the compiler without a database: SQL for psql, on stdout (`--check|--tests|--diff`;
    argparse, `options()` typed); used by the suites, the benchmark, the playground's test and the mutation sweep's
    plan (`mutants/plan.py`)
  - `example/` — docs app: `app_schema.sql`, `docs.authz`, `docs.test.authz` (what most suites set up, and one of
    the playground's examples; the reference uses its rows in places, but its opening policy is another, larger
    one); its own tests pass on its own data (the shares they need, a named test makes); nothing generated is
    kept there
  - `tests/` — all suites; `run_tests.sh` runs them, `ci.sh` runs them on PG 16/17/18 in Docker;
    `tests/golden/` holds the expected generated SQL; `scenario.sql` is the docs app end to end (psql, with
    `-v docs_tests=` the compiled policy tests)
  - `bench/` — `benchmark.sql` (the docs app, bigger; `benchmark_results.txt`) and the scale benchmark (`scale.sh`, pgbench workloads, `results/`, the latest results in its README); the
    default size (20k folders) is for quick dev runs (`--large`, 50k, was the gate's size on the laptop of 2026-10,
    out of use), 4 GB shared buffers; `regress.sh` is the nightly check (10k folders against this machine's
    `baseline.txt`: a baseline belongs to the machine that recorded it, so git ignores it and CI keeps its own in
    the Actions cache); `compare.sh <commit>` runs that commit and this tree in turn on one machine, two rounds
    each, and `compare.py` puts them side by side: how a change's speed is judged (never from two results of two
    machines or two days)
  - `Dockerfile` — Postgres for development and tests: the stock image, python3, git (the review reads the base
    branch with it), the root certificates and the command (build context: repo root)

## Running one suite

For one suite, start a container and run it inside:

    docker build -t rowstile:16 --build-arg PG_MAJOR=16 -f core/Dockerfile .
    docker run -d --name pga16 -e POSTGRES_HOST_AUTH_METHOD=trust -v "$(pwd):/src" rowstile:16
    docker exec -e PGHOST=/var/run/postgresql -e PGUSER=postgres -w /src/core pga16 bash tests/make_owner.sh
    docker exec -e PGHOST=/var/run/postgresql -e PGUSER=authz_owner -e PGSUPERUSER=postgres -w /src/core pga16 bash tests/cli.sh

- The suites run the mounted repository's code; the image only holds a copy of the command for `docker exec`.
- A part's steps run in lanes side by side, on one server (`tests/lanes.sh`): a suite's databases, roles and
  `/tmp` files have names of its own, and a check on `pg_stat_activity` or `pg_locks` names its database. Each
  shell suite's `trap` drops what it made however it ends; where two sessions race, the suite asks the server
  where each one is (`tests/races.sh`), never a `sleep`.
- `ci.sh` starts Postgres with `fsync`, `synchronous_commit` and `full_page_writes` off: the databases last as
  long as the container. Its `wal_level` is `logical`: `governance.sh` copies the audit trail to another database
  by a subscription (skipped, saying why, on a server without it). `difftest.py` asks a snapshot's questions in up to four sessions side by side
  (`DIFFTEST_SESSIONS=1`: one), each user's in one session, two users or more to a session.
- `tests/client_types.py` type-checks the generated TS client (CI's `javascript` job; needs `tsc`, no database);
  `tests/tools_test.py` runs the same check if `tsc` is there (skipped otherwise).
- Benchmark: `createdb b && psql -d b -f example/app_schema.sql && python3 compile_policy.py example/docs.authz > /tmp/docs.sql && psql -d b -v docs_sql=/tmp/docs.sql -f bench/benchmark.sql`

## Conventions

- Generated SQL must be re-appliable: `DROP SCHEMA authz_gen, authz_int CASCADE` then recreate; persistent
  state lives in schema `authz` (`CREATE TABLE IF NOT EXISTS` in `base.py`). The beta started afresh: a database an
  alpha made is applied from scratch, not upgraded, so `base.py` holds no migration from an older layout. From the
  beta on, each release upgrades the databases the one before made: a new column goes last in its `CREATE TABLE`,
  with an `ADD COLUMN IF NOT EXISTS` beside it that gives it to those.
  `tests/upgrade.sh` upgrades databases the release before made (from PyPI: push, apply, reapply, the next
  migration) and compares each with a new database, those tables' columns in order among what it compares.
- Applying: the command runs the compiled SQL in one transaction, as the tables' owner; nothing may
  need a superuser or an extension (later grants on masked columns are reported by `authz.lint()`, not refused). Anything `apply()` creates must also be dropped by `REMOVE_SQL` (`database.py`). `tests/apply.sh`
  applies as a non-superuser owner.
- Migrations: `compile()` records `self.parts`, each with a mode that says what a migration does with
  it (`full`: only the whole script; `always`; `changed`: when its SQL changed, line numbers aside; `created`: also
  when anything was made; `objects`; `tree`). Put new SQL in the right part. A statement that makes something
  indirectly (a DO block) says what, `-- @object <kind> <key>`; a statement that makes nothing belongs to the
  object before it (or the one it names: `INSERT INTO`, `COMMENT ON`). Line numbers in messages at run time go
  through `line_sql`/`line_key` (the table `authz_gen.policy_lines`), never literally, so lines that move change
  no function: only that table's rows (an `objects` part), which a migration of their own writes again.
  `tests/migrate_test.py` checks that a migration leaves what applying whole leaves (those rows too): a new kind of
  change gets a case there.
- Runtime capabilities (what apps call) are `authz.*` functions; compiling, applying, previews and tests belong to
  `authzlib/database.py`, which the command calls.
- Triggers on the app's tables: Postgres runs a table's statement triggers only for statements on that table, not
  for one on a partition or on a table that inherits from it; it copies row triggers to partitions, not to a table
  that inherits, and runs no `AFTER UPDATE` row trigger for a row an update puts in another partition. So
  `CHILD_TRIGGERS` (sqlutil.py; every apply and migration runs it) gives each partition and each table that
  inherits the statement triggers of the tables above whose function is in `authz_int` (but those for TRUNCATE
  alone: emptying one partition is not emptying the table), and each table that inherits their row triggers too;
  `authz.lint()` reports a table made since that lacks them. An `AFTER UPDATE` row trigger needs a statement
  trigger beside it for partitioned tables (`trigger_if_partitioned`, as `<type>__forget` has). `tests/children.sh`
  checks all of it, `tests/around.py` writes straight into the tables under a table: a new trigger gets a case in
  children.sh.
- Tree writes take the type-wide lock.
  `tests/interleave.py` and `tests/stress.sh` (`run_tests.sh --proofs`) must stay green for any locking change.
- Two ways to evaluate a permission, which must agree (the random-change tests check): views (`set_sql`) and
  row checks (`row_sql`). Select rules and `authz.list` use row checks without `point` (lookups into the views,
  which Postgres hashes once for many rows; a recursive permission is first checked against its `__direct` view,
  what the object's own columns give). Write rules and `authz.can` use `point=True`: recursive permissions go
  through their `authz_int."<type>__<perm>__has"` function. Never use point checks in select rules or lists: a
  function call per row makes them slow (`tests/unit_test.py` checks this). `row_sql` orders items cheapest
  first (`item_cost`); keep OR/AND, not CASE.
- A deny inside inheritance (`(viewer or parent.view) and not denied`) is split by `split_denies`
  (compiler.py) into a hidden `view__base` and `view__base and not denied`; `check_denies` refuses a deny that
  doesn't inherit through the same links. Hidden permissions stay off the public surface: enumerate
  `public_perms(t)`, not `t.perms`, for anything users or clients see.
- Keys may have several columns: a composite id is the row's canonical text, so most SQL treats it
  like a text key. Never write `alias.pk` or `src.obj_col` into SQL: use the helpers in compiler.py (`key`,
  `ref`, `key_text`, `key_is`, `key_in`, `key_any`, `subject_id`, `subject_is`); lookups into app tables must
  go column by column (`key_is`), or the table's index isn't used. Ids from callers go through
  `authz_int.canon()` before they are compared with stored shares.
- Who is signed in: `authz.user_id` plus `authz.principal_type` (empty: a user). `authz.uid()` is the
  user only; for "is anyone signed in" use `EXISTS (SELECT 1 FROM authz.principal())`, for who acted (audit,
  `created_by`) `authz_int.actor()`, and in compiled checks `me(st)` for principal type st. Functions that switch
  `authz.user_id` (who, explain, invariants, diff) save and restore `authz.principal_type` too.
- Signed sessions: apps sign in with `authz.act_as()` (or the logins); the four `authz.*` settings are
  believed only with the HMAC in `authz.session` (`authz_int.session_ok()`, PL/pgSQL for its cached plans), except in
  the owner's and superusers' sessions, so the suites and psql may still `SET authz.user_id`. Anything that reads
  the settings goes through `uid()`, `__me`, `actor()` or `scopes_active()`; anything that switches them calls
  `authz_int.sign()` after each switch and after restoring (or `authz_int.act_as(type, id, false)`, like
  `who_among`). A transaction is one principal's: `authz.act_as` and the logins refuse another once someone is
  signed in (`authz_int.one_principal`, AZ716; `authz.sign_out()` for tests), so rowstile's own switches never go
  through them. Trust follows `session_user`, never `current_user`: inside a SECURITY DEFINER function the
  current user is the owner. `tests/sessions.sh` attacks it.
- Apply keeps inheritance tables whose definition (hashed, line numbers aside) and tables (by oid) are unchanged
  (`keep_sql` / `swap_in_kept`): anything that changes what a tree holds must be in its generated SQL,
  or it must not be kept. `tests/keep.sh`.
- Moves and link changes shift stored closure rows (`_shift` in `trees.py`) when only the changed rows' own links
  changed and none loops back below them; otherwise everything below is recomputed. `tests/moves.sh` checks both.
- The sync index (`sync.py`, a preview; `docs/reference/sync.md`) lives in schema `authz_sync`, whose tables
  applying keeps (their rows too, when what they are worked out by didn't change); a policy without sync lines, and
  `rowstile remove`, drop it. Every trigger that may change access calls `authz_int.changed()`, which with sync
  notes the objects in `authz_int.sync_dirty`; a deferred constraint trigger works their readers out again at
  commit, or, with `sync after commit`, notes them in `authz_sync.pending` for `authz.sync_work()`. The sync role
  gets USAGE and SELECT on `authz_sync` and nothing else: applying takes back any other privilege there
  (`sync_extra_grants_sql`), and `authz.lint()` reports a later one, and a sync role that may read a masked column,
  is a superuser, a member of the app role or an owner of a governed table, or lacks BYPASSRLS. `tests/sync.sh`
  checks it, and `tests/difftest.py` holds the index to the reference evaluator.
- New `authz.*` functions: add the name to `GENERATED_FUNCTIONS` (base.py) and, if the app role may call them,
  their signatures to `api_signatures()` (hardening.py). Everything else is admin-only: applying takes back any
  other privilege on the three schemas and what is in them (`extra_grants_sql`, the owner's default privileges
  included), and lint reports later ones.
- SECURITY DEFINER functions: `SET search_path = pg_catalog, pg_temp` with schema-qualified names, or
  `SET search_path FROM CURRENT` when they evaluate the policy's own SQL snippets (the path the search_path part
  sets: the schemas that exist, refused if others may create in one, AZ612).
- A table's columns may have any name, one of a generated function's own too (`p_id`). A function written in SQL
  that reads a table or a row of the app's writes its parameters by position (`$1`, `sqlutil.ROLE_ARG`): there
  Postgres takes a bare name for a column of a table in scope before a parameter, without a word, and the query
  compares the table with itself. `OwnNames` in `tests/unit_test.py` finds any that doesn't, from the compiled SQL
  of the fixed and the hand-answered policies (`tests/kept_names.py` reads each function's names);
  `tests/adversarial.sh` holds a write rule on a link table with a column `p_id`. A row has the same trouble:
  `to_jsonb(n)` is the row `n` only while the table has no column called `n`. A row handed on whole is written
  `n.*` (`to_jsonb(NEW.*)` in a trigger's `WHEN`: the same value, so no ALTER is stopped); the same test finds a
  row named by its alias alone, and `tests/children.sh`'s jobs have columns `n`, `o`, `new` and `old`. In PL/pgSQL
  a bare name that is a column in scope and a name of the function's is refused as ambiguous (42702): where a
  statement reads a table of the app's, a statement's rows or a row laid out (`(SELECT ($1).*)`), write a
  parameter by position (`$1`) and a variable by its block's label (`<<authz__>>` before `DECLARE`, then
  `authz__.v_n`); what a statement puts a value into (`INTO v`, `v :=`, `FOR v IN`) stays bare, and a condition
  beside a query goes in an `IF` of its own (`IF TG_OP = 'TRUNCATE' THEN IF NOT EXISTS (...)`). The test reads
  each piece of a body apart, and `tests/hand_answers.sh --kept-names` runs the hand-answered policies again on
  tables that have a column of every name the generated SQL keeps and of every word it writes by itself (some 500 a
  table): a query's column or one of rowstile's own tables', written bare inside a query on a table of the app's, is
  that table's column where it has one, so name it by its query (`c.id`).
- Mutating API functions call `authz_int.check_writable()` first (scopes / view-as are read-only).
- Anything a later function calls must exist before it in `compile()` output order, or be plpgsql (bodies
  resolve at run time); SQL-language functions referencing later objects sit between
  `check_function_bodies = off/on`. Things that may add views (`insight`, invariants, masked views) are
  generated before `self.view_sql` is expanded.
- Every behaviour change gets a check in the relevant suite; `tests/difftest.py` compares the database
  against an independent reference evaluator (`authzlib/evaluate.py`, also the review's) — keep it in sync with
  language changes. The two share the parser, so `HandAnswers` (`tests/unit_test.py`) holds the evaluator to
  answers worked out by hand from the reference (where only the database can give one, a policy with named tests in
  `tests/hand/`, which `tests/hand_answers.sh` runs): a new language form gets a case there, and, if it belongs to the
  core (a kind of source, an operator), a place in `tests/small.py`'s list (`sources`, `expressions`), whose
  COUNTS then change (`--count`); `gh workflow run nightly.yml -f only=small` checks the whole list (fourteen
  jobs), each night's soak a fourteenth of it.
  A change to generated SQL shows up in `tests/golden/`: update it deliberately and read the diff.
- Error messages name the policy line and end with a code: `fail(loc, msg, "AZ201")`. A new kind of mistake
  gets a code and a page in `authzlib/errors.py` (the page's mistake must give its code, its fix must compile;
  `unit_test.py --update` writes `docs/errors/`), and a case in `tests/policy_errors.py`. What the runtime raises
  (what apps see) carries its code in the HINT instead, `rowstile help AZ709`, so the message stays as the SDKs
  read it; `ErrorCodes` in `tests/unit_test.py` finds any RAISE without a code. Each RAISE is asked for by its own
  words by some check (an SQLSTATE alone can't tell which guard refused): `Guards` in `tests/unit_test.py` fails
  when none does, and lists the few whose words another guard's message has too.
- Imports: each run of the command imports only what it uses (`Imports` in `tests/unit_test.py`): a module only
  some commands need (the compiler, migrate.py, ssl, hashlib) is imported in the function that needs it, never at the
  top of `rowstile_cli.py`, `database.py` or `pgwire.py`.
- What the rules read is hidden: every view and the functions the rules call (`__has`, `__links`, `__check`,
  `__ids`) are in `authz_int`, where the app role has no USAGE and can't name them. Postgres keeps a policy, a
  BEGIN ATOMIC body and a trigger's `WHEN` as read when applied and checks a schema only when a name is looked up,
  so the rules still use them; the app role keeps SELECT or EXECUTE on what the rules use and nothing else
  (`extra_grants_sql`, lint). `authz_gen` holds no views: only `policy_lines` and the rules' own functions. A rule
  on a column is checked in its trigger's `WHEN`. Never name `authz_int` in text read at run time as the app role
  (a plpgsql body, dynamic SQL). `tests/own_ids.sql` (`adversarial.sh`) checks that nothing the app role may name
  tells apart two objects the API can't.
- Refused writes: every `WITH CHECK` is `check OR authz_gen."<table>:<cmd>:refuse"((t.*)::table)` (a whole-row
  value: it names no column, so a column no rule reads can be dropped); the explaining functions are PL/pgSQL in
  `authz_gen`, run as the app role, answer only for a new row or one the user may select
  (`authz_int."<table>:seen"`), and must never leak what `authz.explain` wouldn't. Anything that evaluates a
  policy's `with_check` text on rows (difftest) must drop the refuse call (`without_refusals`).
- No value of an app table's row type in a BEGIN ATOMIC body or a trigger's `WHEN` (a row parameter read, a
  `NULL::table`): from PostgreSQL 16.16, 17.12 and 18.7 on (CVE-2026-6460) it stops the app's `ALTER TABLE`s that lay
  the rows out again (a column added `NOT NULL` with a default or generated, a column's type). The functions that
  check a rule on a row (`<table>:<cmd>:items`, `<table>:column ...:holds`) are bodies in a string that run as the
  owner (`SECURITY DEFINER SET search_path FROM CURRENT`), reading only the row: what reads more is in definer views
  and functions already. They take the caller's role (`authz__role`), which a condition's `current_user`,
  `current_role` and `user` name there (`sqlutil.as_caller`); a trigger's `WHEN` passes the row as `to_jsonb(NEW)`.
  `tests/children.sh` runs those ALTERs.
- Named tests never run on `apply` (they write); each runs in a subtransaction that always rolls back. New test
  syntax gets a case in `tests/policy_errors.py` and the grammars: `editor/syntaxes/` (TextMate) and
  `editor/tree-sitter-authz/` (Tree-sitter: `grammar.js`, then `npx tree-sitter generate`, a corpus case).
- The language server (`core/cli/lsp.py`) parses and compiles. From a database it only reads the tables' and columns'
  names, once, for completion, and only with `database` in rowstile.toml; applying, pushing and testing belong to
  `rowstile dev`. `tests/lsp_test.py` drives it over the protocol; its part with a database runs where `createdb`
  works.

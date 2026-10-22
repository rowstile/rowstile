# rowstile

Access rules for Postgres: a policy language (`.authz`) that the `rowstile` command compiles into row-level
security (views, trigger-maintained closure tables, RLS policies and `authz.*` SQL functions) and applies as
plain SQL, as the tables' owner. No extension, no superuser. PostgreSQL 16, 17 and 18.
User-facing docs: `README.md`, then `docs/reference/` (read them first). Terms in `CONTEXT-MAP.md` and `core/CONTEXT.md`.

## Layout

- `core/` — rowstile itself: the compiler, the command, their tests (main work happens here)
  - `authzlib/` — compiler, standard library only; `__version__` in `__init__.py` is the version the command
    and the packages carry (`packaging/version.py X.Y.Z` sets it everywhere; `unit_test.py` checks they
    agree). `Compiler` (`assembled.py`; `authzlib.Compiler`, imported when first asked for) is a stack of mixins:
    - `parse.py` — parser (types, relations, perms, rules, scopes, caveats, invariants, tests, includes;
      includes come from a `files` map when given, never from disk)
    - `compiler.py` (Core) — validation, recursion/SCC analysis, per-relation/permission views
    - `trees.py` — closure tables for inheritance + their triggers
    - `output.py` — assembles the final SQL (`compile()`), RLS policies, `can/list/perms`, sharing API, masked views
    - `insight.py` — `who`, `explain`, `list_shares`
    - `identity.py` — scopes, API keys, JWT login, view_as, sync_members, audit helper
    - `governance.py` — audit/feed triggers, requests, break_glass, reviews, invariants, diff (`diff_parts`)
    - `hardening.py` — `authz.lint()`
    - `devtools.py` — graph (Mermaid), clients (py, ts; with `Refused`, `NotFound`, `refusal`, `expect`, `who_among`;
      `ts-sdk`: only the names, for apps on the TypeScript SDK)
    - `testing.py` — policy tests: the unnamed section, named tests (`given`, `as user X allowed|refused|sees`;
      `with scope a, b` after who: the line as a key limited to those scopes), invariants,
      compiled into one plpgsql function `pg_temp.authz_policy_tests()` returning a row per check
    - `refusals.py` — refused writes that say why, `authz.explain_rule`, `authz.who_among`
    - `draft.py` — a first policy from the catalog (`rowstile init`)
    - `base.py` — persistent tables (`authz.shares`, `authz.audit`, ...), migrations, `GENERATED_FUNCTIONS`
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
      counterexample, shrunk link by link
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
  - `cli/` — the command runs on Python 3.11 or newer, standard library only: `rowstile` (`rowstile_cli.py`: compiles, and runs `authzlib.database` over its own connection; reads
    included files and `rowstile.toml` from disk; `dev` watches and runs the loop), `lsp.py` (the
    language server, `rowstile lsp`), `mcp.py` (the MCP server for coding agents, `rowstile mcp`: each tool runs
    the command once; `tests/mcp_test.py`), `init.py` (`rowstile init`), `migrations.py` (a migration's files for
    each tool: Alembic, Prisma, Drizzle Kit, SQL, goose, dbmate, Flyway), `stack.py` (the app's stack, for
    `init`), `studio.py` and `studio/` (Studio: a local web page and its JSON API; read-only transactions unless
    `--write` or `dev`; localhost and a token; `tests/studio_test.py`) and `pgwire.py` (stdlib Postgres client,
    SCRAM, notices, URLs, `script()` for many statements)
  - `compile_policy.py` — the compiler without a database: SQL for psql (`--check|--tests|--diff`; argparse, `options()` typed);
    used by the tests, the editor task and the benchmark
  - `example/` — docs app: `app_schema.sql`, `docs.authz`, `docs.test.authz` (what most suites set up, and one of
    the playground's examples; the reference uses its rows in places, but its opening policy is another, larger
    one); its own tests pass on its own data (the shares they need, a named test makes); nothing generated is
    kept there
  - `tests/` — all suites; `run_tests.sh` runs them, `ci.sh` runs them on PG 16/17/18 in Docker;
    `tests/golden/` holds the expected generated SQL; `scenario.sql` is the docs app end to end (psql, with
    `-v docs_tests=` the compiled policy tests)
  - `bench/` — `benchmark.sql` (the docs app, bigger; `benchmark_results.txt`) and the scale benchmark (`scale.sh`, pgbench workloads, `results/`, the latest results in its README); the
    default size (20k folders) is for quick dev runs, `--large` (50k) is the gate's size on the dev laptop, 4 GB
    shared buffers; `regress.sh` is the CI check (10k folders against `baseline.txt`)
  - `Dockerfile` — Postgres for development and tests: the stock image, python3, the command
    (build context: repo root)
- `editor/` — `test.sh` (in containers: the grammar, the Zed build, the VS Code extension built as its README says
  and `extension_test.js` against stand-ins for VS Code, Neovim set up as the README says); the VS Code extension:
  TextMate grammar (the site highlights ```authz with it too), and `extension.js` starting `rowstile lsp`;
  `tree-sitter-authz/` (the Tree-sitter grammar and its queries, for Zed, Helix and Neovim; `src/` is generated and
  committed, editors build from it); `zed/` (the Zed extension: its queries are copies of the grammar's, `Editors`
  in `unit_test.py`)
- `review-ci/` — the review for CI: `github/action.yml` (a composite action; it installs the release its tag names
  from PyPI, or with `version: source` this checkout's command, as `.github/workflows/ci.yml` does) and
  `gitlab/rowstile-review.gitlab-ci.yml`
- `examples/filemanager/` — the first adopter (uses only the public surface, `check_public_surface.py`):
  `db/` (migrations, `policy.authz`, `migrate.py`), `backend/` (FastAPI, uv), `frontend/` (React, Vite),
  `docker-compose.yml` (rowstile image from this repo, RustFS); `test.sh` runs its tests
- `examples/messenger/` — the second adopter, a WhatsApp-style app built to show what rowstile takes off an app
  (same stack and rules as the file manager: public surface only, `check_public_surface.py`); `test.sh` runs its tests
- `sdk/python/` — the `rowstile` Python package: the Python SDK (`rowstile`: FastAPI, SQLAlchemy, psycopg, asyncpg,
  Alembic, pytest) and the command, which `hatch_build.py` puts inside it (`rowstile/_command`).
  It holds no rowstile logic: it signs transactions in and translates the `authz.*` answers
- `sdk/typescript/` — the TypeScript SDK (`@rowstile/client`, `/pg`, `/postgres`, `/prisma`, `/drizzle`, `/next`,
  `/react`, `/vitest`), one package per folder, built with `npx tsc -b sdk/typescript`. The repository
  root's `package.json` is the npm workspace for these packages and `integrations/nextjs` (one React, one pg);
  `npm ci` at the root. Like the Python SDK it holds no rowstile logic
- `integrations/<stack>/` — each SDK's conformance suite: a small app and the checks listed in `integrations/README.md`;
  `integrations/fastapi/test.sh` (uv, Docker), `integrations/nextjs/test.sh` (Next.js, Prisma 7, Vitest, Docker)
- `packaging/` — how rowstile is installed: `npm/build.mjs` (the `rowstile` npm package and one
  `@rowstile/cli-<platform>` per platform with a standalone Python), `docker/Dockerfile` (the command's image);
  `test.sh` installs each on a clean machine; `version.py` sets the version (X.Y.Z, X.Y.Z-alpha.N,
  X.Y.Z-beta.N, X.Y.Z-rc.N or X.Y.Z-dev: the grammar of `core/authzlib/versions.py`);
  `npm_latest.py` moves npm's `latest` to where `next` is while no final release exists (the release's npm
  job, and by hand `gh workflow run release.yml -f latest=true`).
  `server.json` (the repository's root) is the MCP server's entry in the official registry: it names the npm
  package, whose `mcpName` must be its name (`Version` in `unit_test.py`), and the release publishes it last.
  `.github/workflows/release.yml` publishes them on a tag: to private places while the repository is private
  (GitHub Packages, the GitHub release), to PyPI, npm and ghcr.io once public. The workflows run on
  GitHub's runners (`ubuntu-latest`)
- `demo/` — the recording at the top of the README (`demo.gif`): `record.sh` runs `demo.tape` in a terminal
  recorder in a container, on the guide's own app (`files.py` takes it from `docs/getting-started.md`); made
  again by hand when what the commands print changes (`Demo` in `unit_test.py` checks the tape still fits)
- `playground/` — rowstile in the browser: the compiler in Pyodide (a worker), the SQL in PGlite; `core.mjs` is the
  engine, `test.mjs` runs it in Node, `browser_test.mjs` the page in headless Chrome, `build.mjs` writes `dist/`
  (its examples are read from the repository: the getting-started guide's own, the docs app, the cookbook's
  recipes)
- `README.md` — the landing page: the pitch, installing, the docs, the folders. `core/README.md` is for working
  on the core folder (what's where, the test suites)
- `docs/` — `reference/` (the reference by subject: `language.md`, `app-code.md`, `identity.md`,
  `governance.md`, `tools.md`, `migrations.md`, `review.md`, `guarantees.md`, `limits.md`),
  `installing.md` (the site's Installing page: it holds the README's install lines, `DocPages` checks),
  `getting-started.md` (run as written by `tests/docs_test.sh`), `cookbook.md` + `cookbook/` (the index, and
  the recipes: each is `cookbook/<name>.md` beside `cookbook/<name>/` with `schema.sql`, `policy.authz`,
  `tests.authz`, `rows.sql` for the playground, `rowstile.toml` (so `rowstile dev` runs in a copy of the folder)
  and, where `SELECT *` on the first governed table isn't the question to ask there, `ask.sql`;
  `tests/cookbook.sh` applies and tests each, proves its invariants, runs `rowstile dev --once` in a copy, runs
  each SQL block its page shows (as user 1, the app role; `<!-- not run: why -->` before one it can't), compares
  each `$ rowstile ...` output with what the command prints, and checks every policy and test line its page shows
  is in its files; the site and the playground list them from the folders,
  and `/playground/#e=<name>` opens one), `troubleshooting.md`,
  `operations.md`, `managed-postgres.md` (the setup on a managed service; Neon and Supabase, as tried),
  `signed-urls.md`, `comparison.md` and `compare/` (a page per alternative, titled `# rowstile and <it>`, which
  the site lists from the folder: what they say of another project is quoted from its docs with the day they
  were read, and wants reading again each quarter (`docs/compare_readings.py`, the nightly's `readings` job, fails
  once a reading is older); `ComparePages` checks what they say of rowstile), `stacks/` (a page per stack; every line of code in them is in a
  conformance app, `StackPages` in `tests/unit_test.py`), `errors/` (a page per error code, written from
  `authzlib/errors.py` by `unit_test.py --update`)
- `context7.json` — for an index of docs that coding agents ask (Context7): the folders it reads, and what an
  agent should know first (`LlmsTxt` in `unit_test.py` checks its paths and its limits)
- `llms.txt` — for agents: what to know, and the links; `docs/llms_full.py` puts those files in one
  (`llms-full.txt`, built when the docs are published, not committed)
- `site/` — the docs site (VitePress; own `package.json`, like `playground/`): the Markdown stays where it is,
  `pages.mjs` says which files are pages and at which address, and turns each link (written relative to its
  file, for GitHub) into the page's address or the file on GitHub; a link to a missing file or page fails the
  build. `build.mjs` writes `dist/`: the pages, `/playground/`, each page's Markdown (`/getting-started.md`),
  `llms.txt` pointing to those, `llms-full.txt`. Its own pages: `index.md` and `problems/` (the SDKs' problem
  `type` URLs). A new doc page goes in `PAGES`, with its sentence in `DESCRIPTIONS` (what a search result and a
  shared link show; a page without one fails the build), and in the sidebar (`.vitepress/config.mts`). `build.mjs`
  also checks that the sitemap lists every page, and writes `robots.txt`. The blog: a post is
  `docs/blog/<date>-<slug>.md` (its title, `*Author's Name, <date>*`, then a first paragraph, its summary),
  listed in `docs/blog/README.md` (the index); `pages.mjs` reads them (`POSTS`, `readPost`), `blog.mjs` writes the
  Atom feed (`/blog/feed.xml`), `blog_test.mjs` checks both on made-up posts. With no post there is no blog on
  the site. `assets/` holds the mark (`mark.svg`:
  the tab's icon, the navigation's) and what is rendered from it and committed, by `node site/assets/render.mjs`
  with a headless Chrome or Edge: `card.png` (what a shared link shows, from `card.html`) and `editor/icon.png`.
  `.github/workflows/site.yml` deploys it to GitHub Pages (rowstile.dev), built from a release tag. Between
  releases a site tag (`site-vN`) publishes `docs/blog/` and `docs/compare/` alone, on the release the site
  shows: `source.mjs` is the rule (what a tag is built from, and the checkout), `source_test.mjs` its test,
  `RELEASING.md` the steps
- `.github/workflows/ci.yml` — on each push: `tests/unit_test.py` and the type checks, every suite on PG 16
  (`ci.sh`) and what depends on the version on 17 and 18 (`ci.sh --short`), the examples, the conformance suites,
  the editors, packaging, the site. The suites run in parts, a job each, side by side (`ROWSTILE_PART`;
  `run_tests.sh` names them and puts each step in one: a new step goes in a unit inside an `if part ...` (a
  function, then `unit PART SECONDS NAME`: a part's units run in lanes, `tests/lanes.sh`), and a new part
  in the workflows' lists, which `Delivery` in `unit_test.py` checks); the jobs `postgres (16)` and the like,
  which `main` requires, only wait for their parts. `nightly.yml` (main) — every suite on 17 and 18, the proofs
  (`--proofs`) on each version, the soak (new seeds each night, one version in turn, in five parts side by side;
  by hand, several at once on the three versions: `gh workflow run
  nightly.yml -f only=soak -f soaks=7`), the conformance suites on 17 and 18 and on 16
  through PgBouncer (`integrations/pooler.sh`), the migrations `rowstile migrate` writes run by goose,
  dbmate and Flyway (`tests/migration_tools.sh`), then
  the benchmark check (`gh workflow run nightly.yml -f only=bench` runs it alone; it judges speed against
  the runners' own baseline, not the gate's limits). `ci.sh` writes its logs to `/tmp`
- `.github/workflows/scorecard.yml` — the OpenSSF Scorecard, weekly and on `main`: published at scorecard.dev
  (the README's badge), each check's reason in the run's files, the findings under Security, Code scanning.
  Publishing restricts the workflow: only its listed actions, no `run` steps, no `env`
- `docs/threat-model.md` — the trust boundary and what `tests/adversarial.sh` checks

## Running

Tests need Postgres, python3 and a role with CREATEDB and CREATEROLE; they create/drop databases named `authz_*`.
Every suite runs as a non-superuser owner: `run_tests.sh`, started as a superuser, makes `authz_owner` and runs
as it (`PGSUPERUSER` names the superuser, for the few checks that a superuser's connection is refused). The
simplest is Docker, from the repo root:

    core/ci.sh                   # run_tests.sh --quick on 16, 17 and 18, each in a fresh container
    core/ci.sh --full 16         # the full run (~15 minutes) on one version
    core/ci.sh --short 17 18     # what depends on the version (what CI runs on 17 and 18 for each push)
    ROWSTILE_PART=command core/ci.sh 16   # one part of a run (`run_tests.sh` names them: unit, policy, command, random)
    ROWSTILE_LANES=1 core/ci.sh 16        # a part's steps one after the other (else in 3 lanes side by side)
    core/ci.sh --coverage 16     # and what the suites run of authzlib and cli: .ci/coverage-16/report.txt says
                                 # what nothing runs (tests/coverage_report.py; CI's coverage job, --diff on PRs)
    python3 core/tests/unit_test.py   # a second, no database; --update rewrites tests/golden/ after an intended change

For one suite, start a container and run it inside:

    docker build -t rowstile:16 --build-arg PG_MAJOR=16 -f core/Dockerfile .
    docker run -d --name pga16 -e POSTGRES_HOST_AUTH_METHOD=trust -v "$(pwd):/src" rowstile:16
    docker exec -e PGHOST=/var/run/postgresql -e PGUSER=postgres -w /src/core pga16 bash tests/make_owner.sh
    docker exec -e PGHOST=/var/run/postgresql -e PGUSER=authz_owner -e PGSUPERUSER=postgres -w /src/core pga16 bash tests/cli.sh

- The suites run the mounted repository's code; the image only holds a copy of the command for `docker exec`.
- A part's steps run in lanes side by side, on one server (`tests/lanes.sh`): a suite's databases, roles and
  `/tmp` files have names of its own, and a check on `pg_stat_activity` or `pg_locks` names its database.
- `ci.sh` starts Postgres with `fsync`, `synchronous_commit` and `full_page_writes` off: the databases last as
  long as the container. Its `wal_level` is `logical`: `governance.sh` copies the audit trail to another database
  by a subscription (skipped, saying why, on a server without it). `difftest.py` asks a snapshot's questions in up to four sessions side by side
  (`DIFFTEST_SESSIONS=1`: one), each user's in one session, two users or more to a session.
- Everything is LF (`.gitattributes`). New scripts are executable in git (`chmod +x`; `Executable` in
  `unit_test.py` checks).
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
  no function. `tests/migrate_test.py` checks that a migration leaves what applying whole leaves: a new kind of
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
  `authz_int.sign()` after each switch and after restoring (or `act_as` when it runs as the caller, like
  `who_among`). Trust follows `session_user`, never `current_user`: inside a SECURITY DEFINER function the
  current user is the owner. `tests/sessions.sh` attacks it.
- Apply keeps inheritance tables whose definition (hashed, line numbers aside) and tables (by oid) are unchanged
  (`keep_sql` / `swap_in_kept`): anything that changes what a tree holds must be in its generated SQL,
  or it must not be kept. `tests/keep.sh`.
- Moves and link changes shift stored closure rows (`_shift` in `trees.py`) when only the changed rows' own links
  changed and none loops back below them; otherwise everything below is recomputed. `tests/moves.sh` checks both.
- New `authz.*` functions: add the name to `GENERATED_FUNCTIONS` (base.py) and, if the app role may call them,
  their signatures to `api_signatures()` (hardening.py). Everything else is admin-only: applying takes back any
  other privilege on the three schemas and what is in them (`extra_grants_sql`, the owner's default privileges
  included), and lint reports later ones.
- SECURITY DEFINER functions: `SET search_path = pg_catalog, pg_temp` with schema-qualified names, or
  `SET search_path FROM CURRENT` when they evaluate the policy's own SQL snippets (the path the search_path part
  sets: the schemas that exist, refused if others may create in one, AZ612).
- Mutating API functions call `authz_int.check_writable()` first (scopes / view-as are read-only).
- Anything a later function calls must exist before it in `compile()` output order, or be plpgsql (bodies
  resolve at run time); SQL-language functions referencing later objects sit between
  `check_function_bodies = off/on`. Things that may add views (`insight`, invariants, masked views) are
  generated before `self.view_sql` is expanded.
- A feature lands with its entry in `core/tests/features.py` (what it covers, its page, its checks, and for one that
  decides access its check against the reference evaluator): `Features` in `unit_test.py` fails on a new
  `authz.*` function, command, flag, language form, error code or export that no feature covers.
- Every behaviour change gets a check in the relevant suite; `tests/difftest.py` compares the database
  against an independent reference evaluator (`authzlib/evaluate.py`, also the review's) — keep it in sync with
  language changes. The two share the parser, so `HandAnswers` (`tests/unit_test.py`) holds the evaluator to
  answers worked out by hand from the reference: a new language form gets a case there, and, if it belongs to the
  core (a kind of source, an operator), a place in `tests/small.py`'s list (`sources`, `expressions`), whose
  COUNTS then change (`--count`); seven soaks at once check the whole list (`gh workflow run nightly.yml -f
  only=soak -f soaks=7`), each night's a seventh of it.
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
- Types: all Python is strongly typed. `uvx ty@0.0.56 check && uvx ruff@0.15.12 check && uvx ruff@0.15.12
  format --check` from the root (CI's `unit` job): ty checks the types (`ty.toml`, every rule an error), Ruff
  the lint, that every function is annotated (`ruff.toml`, `ANN`, no exceptions), and the layout: run `uvx
  ruff@0.15.12 format` before a commit (120 columns; what the command generates, the apps' clients and the
  Alembic revisions, is left as generated). `.githooks/pre-commit` refuses staged Python that isn't laid out
  (on in a clone after `git config core.hooksPath .githooks`); `Layout` in `unit_test.py` checks the hook, CI
  and these rules name one version of Ruff. A commit that only lays code out goes in `.git-blame-ignore-revs`
  once it is on `main` (its full hash; the same test checks). ty's root settings cover the standard-library code; what needs
  a package's environment has its own (`uv sync` it first), `--project` sdk/python (the fastapi app's
  environment), integrations/fastapi, examples/filemanager and examples/messenger (their backends'); CI's `unit`
  job runs them all. Test code types the JSON it checks as `Answer = Any`, one alias, named; app code types rows
  as psycopg's `DictRow`. Python 3.11 syntax, standard library only (no `typing.override`, 3.12). A policy
  expression is a NamedTuple per kind (`parse.Expr`: `Or`, `And`, `Not`, `Cond`, `Ref`, `Arrow`, `ArrowOn`):
  build them with the class, and in typed code take them apart with `match`/`isinstance`, not `node[0]`.
- JavaScript is typed too: JSDoc, checked by `tsc` with `checkJs` and `strict`, one `tsconfig.json` per folder with its
  environment's types (playground, site, editor, editor/tree-sitter-authz, packaging/npm; Studio's page:
  `core/cli/tsconfig.studio.json`); CI's `javascript` job runs them after `npm ci` in each. The page's API answers
  are typedefs matching what the Python sends (`studio.py`, `core.mjs`); keep them in step.
- Words: see `core/CONTEXT.md` (share, not grant; role means a runtime role; app role for the Postgres one).
- Prose style in docs and messages: plain words, short sentences.
- Promises in the docs: on `docs/reference/`, `docs/threat-model.md` and `docs/how-it-is-checked.md`, a sentence
  that says always, never, can't, only, refuses, keeps or removes ends with
  `<!-- checked: tests/<suite> "<its label>" -->` (text that suite's file holds) or `<!-- unchecked: why -->`,
  written after it on the line it ends on, no `--` or `>` inside (`Promises` in `tests/unit_test.py` has the rule). Every code block of `docs/reference/`
  runs in `tests/reference.sh`, or a comment right before it says why not: `<!-- not run: why -->`.

- What the rules read is hidden: every view and the functions the rules call (`__has`, `__links`, `__check`,
  `__ids`) are in `authz_int`, where the app role has no USAGE and can't name them. Postgres keeps a policy, a
  BEGIN ATOMIC body and a trigger's `WHEN` as read when applied and checks a schema only when a name is looked up,
  so the rules still use them; the app role keeps SELECT or EXECUTE on what the rules use and nothing else
  (`extra_grants_sql`, lint). `authz_gen` holds no views: only `policy_lines` and the rules' own functions. A rule
  on a column is checked in its trigger's `WHEN`. Never name `authz_int` in text read at run time as the app role
  (a plpgsql body, dynamic SQL). `tests/own_ids.sql` (`adversarial.sh`) checks that nothing the app role may name
  tells apart two objects the API can't.
- Refused writes: every `WITH CHECK` is `check OR authz_gen."<table>:<cmd>:refuse"((t.*)::table)` (a whole-row
  value: it names no column, so a column no rule reads can be dropped); the explaining functions are BEGIN ATOMIC in
  `authz_gen`, run as the app role, answer only for a new row or one the user may select
  (`authz_int."<table>:seen"`), and must never leak what `authz.explain` wouldn't. Anything that evaluates a
  policy's `with_check` text on rows (difftest) must drop the refuse call (`without_refusals`).
- Named tests never run on `apply` (they write); each runs in a subtransaction that always rolls back. New test
  syntax gets a case in `tests/policy_errors.py` and the grammars: `editor/syntaxes/` (TextMate) and
  `editor/tree-sitter-authz/` (Tree-sitter: `grammar.js`, then `npx tree-sitter generate`, a corpus case).
- The language server (`core/cli/lsp.py`) parses and compiles. From a database it only reads the tables' and columns'
  names, once, for completion, and only with `database` in rowstile.toml; applying, pushing and testing belong to
  `rowstile dev`. `tests/lsp_test.py` drives it over the protocol; its part with a database runs where `createdb`
  works.
- Adopters' `test.sh` start from an empty database (`docker compose down -v`): migrations must work before the
  first apply (`authz.uid()` doesn't exist yet: use plpgsql bodies).

## Changes and releases

`CONTRIBUTING.md` and `RELEASING.md` are the rules; in short:
- Work on a short-lived branch from `main`, named for what it does, and land it through a pull request (CI runs
  on pull requests and `main`). Never commit to `main` directly.
- Commits are signed off (`git commit -s`; `.github/workflows/pr.yml` checks), and their subject says what
  changed, in plain words.
- A change users will notice gets a line under **Unreleased** in `CHANGELOG.md` (Added, Changed, Fixed,
  Upgrading); the same check asks when `core/authzlib`, `core/cli`, `sdk`, `review-ci`, `packaging` or
  `editor` change (label `no changelog` otherwise).
- Merging: the maintainer's pull requests rebased, outside ones squashed, a merge commit only when a commit
  must stay reachable.
- The version: `packaging/version.py` sets it everywhere (X.Y.Z, X.Y.Z-alpha.N, X.Y.Z-beta.N, X.Y.Z-rc.N, or
  X.Y.Z-dev on `main` between releases), in the one grammar `authzlib/versions.py` holds (a version's alphas,
  then its betas, its candidates, the version: the downgrade guard, AZ616, orders them so). Apply, push and migrations record `authzlib.BUILD` (a `-dev` version plus a hash of
  `authzlib/`; a release's own version otherwise), and apply and push compare it, so two builds of `main`
  don't trust each other's databases. The lock file's header names `__version__`, and a new version alone
  is no migration (`always` in the lock hashes the steps every migration runs).

## Known limits / open ideas

See "Limits" in `docs/reference/limits.md`: no sharding, no SCIM endpoint (sync
function only), HS256-only JWTs.

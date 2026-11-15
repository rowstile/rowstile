# rowstile

Access rules for Postgres: a policy language (`.authz`) that the `rowstile` command compiles into row-level
security (views, trigger-maintained closure tables, RLS policies and `authz.*` SQL functions) and applies as
plain SQL, as the tables' owner. No extension, no superuser. PostgreSQL 16, 17 and 18.
User-facing docs: `README.md`, then `docs/reference/` (read them first). Terms in `CONTEXT-MAP.md` and
`core/CONTEXT.md`.

Each area's detail is in `.claude/rules/`, loaded when its files are read: `core.md` (the compiler, the command,
the suites), `sdks.md` (the SDKs, the conformance suites), `examples.md`, `editor.md`, `docs-site.md` (the docs,
the site, the playground), `delivery.md` (CI, packaging, releases), `python.md`, `javascript.md`.

## Layout

- `core/` — rowstile itself: `authzlib/` (the compiler, standard library only), `cli/` (the command, the
  language server, the MCP server, Studio), `tests/` (all suites, `run_tests.sh`, `ci.sh`), `bench/`, `example/`
  (the docs app most suites set up)
- `sdk/` — the SDKs: Python and TypeScript, and in preview Go, .NET, Ruby, Java, Rust, Elixir and PHP; no rowstile
  logic in any of them. `integrations/<stack>/` — each SDK's and each sync engine's conformance suite
- `examples/` — three adopters on the public surface alone: `filemanager/`, `messenger/`, `helpdesk/`
- `editor/` (VS Code, Zed, Tree-sitter), `review-ci/` (the review for CI), `packaging/` (PyPI, npm, the image),
  `demo/`, `playground/` (rowstile in the browser), `site/` (the docs site), `docs/` (the docs, the reference)
- `.github/workflows/` — `ci.yml` on each pull request and push, `nightly.yml`, `release.yml`, `site.yml`

## Running

Tests need Postgres, python3 and a role with CREATEDB and CREATEROLE; they create/drop databases named `authz_*`.
Every suite runs as a non-superuser owner: `run_tests.sh`, started as a superuser, makes `authz_owner` and runs
as it (`PGSUPERUSER` names the superuser, for the few checks that a superuser's connection is refused). The
simplest is Docker, from the repo root:

    core/ci.sh                   # run_tests.sh --quick on 16, 17 and 18, each in a fresh container
    core/ci.sh --full 16         # the full run on one version (over an hour; nightly runs it in parts side by side)
    core/ci.sh --short 17 18     # what depends on the version (what CI runs on 17 and 18 for each push)
    ROWSTILE_PART=command core/ci.sh 16   # one part of a run (`run_tests.sh` names them: unit, policy, command, random)
    ROWSTILE_LANES=1 core/ci.sh 16        # a part's steps one after the other (else in 3 lanes side by side)
    core/ci.sh --coverage 16     # and what the suites run of authzlib and cli: .ci/coverage-16/report.txt says
                                 # what nothing runs (tests/coverage_report.py; CI's coverage job, --diff on PRs;
                                 # --statements: the PL/pgSQL too, held to tests/plpgsql_floor.txt)
    python3 core/tests/unit_test.py   # two to three minutes, no database; --update rewrites tests/golden/ after
                                      # an intended change

- Everything is LF (`.gitattributes`), but Windows' batch files (`*.cmd`, CRLF when checked out). New scripts
  are executable in git (`chmod +x`; `Executable` in `unit_test.py` checks).

## Every change

- A feature lands with its entry in `core/tests/features.py` (what it covers, its page, its checks, and for one that
  decides access its check against the reference evaluator): `Features` in `unit_test.py` fails on a new
  `authz.*` function, command, flag, language form, error code or export that no feature covers.
- Words: see `core/CONTEXT.md` (share, not grant; role means a runtime role; app role for the Postgres one).
- Prose style in docs and messages: plain words, short sentences.

## Branches, commits and releases

`CONTRIBUTING.md` and `RELEASING.md` are the rules; in short:
- Work on a short-lived branch from `main`, named for what it does, and land it through a pull request (CI runs
  on pull requests and `main`). Never commit to `main` directly.
- Commits are signed off (`git commit -s`; `.github/workflows/pr.yml` checks), and their subject says what
  changed, in plain words.
- A change users will notice gets a line under **Unreleased** in `CHANGELOG.md` (Added, Changed, Removed, Fixed,
  Upgrading, in that order); the same check asks when `core/authzlib`, `core/cli`, `sdk`, `review-ci`, `packaging` or
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
function only), JWTs checked in SQL when signed HS256 or RS256 (ES256 and EdDSA go through the backend).

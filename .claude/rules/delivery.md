---
paths:
  - ".github/**"
  - "packaging/**"
  - "review-ci/**"
  - "demo/**"
  - "server.json"
  - "RELEASING.md"
  - "CHANGELOG.md"
---

# CI, packaging and releases

The workflows, how rowstile is packaged and released, the review for CI, the demo.

- `review-ci/` — the review for CI: `github/action.yml` (a composite action; it installs the release its tag names
  from PyPI, or with `version: source` this checkout's command, as `.github/workflows/ci.yml` does) and
  `gitlab/rowstile-review.gitlab-ci.yml`
- `packaging/` — how rowstile is installed: `npm/build.mjs` (the `rowstile` npm package and one
  `@rowstile/cli-<platform>` per platform with a standalone Python), `docker/Dockerfile` (the command's image);
  `test.sh` installs each on a clean machine (the machines pinned in `machines/Dockerfile`), starts the Linux
  platform packages and reads the macOS and Windows ones (`npm/platforms.py`: the Python, the libraries and the
  modules the command loads are there); the command's files the Python and npm packages carry are listed once,
  in `sdk/python/command-files.txt`; `changelog.py` takes a release's notes from `CHANGELOG.md`;
  `version.py` sets the version (X.Y.Z, X.Y.Z-alpha.N,
  X.Y.Z-beta.N, X.Y.Z-rc.N or X.Y.Z-dev: the grammar of `core/authzlib/versions.py`);
  `npm_latest.py` moves npm's `latest` to where `next` is while no final release exists (the release's npm
  job, and by hand `gh workflow run release.yml -f latest=true`).
  `server.json` (the repository's root) is the MCP server's entry in the official registry: it names the npm
  package, whose `mcpName` must be its name (`Version` in `unit_test.py`), and the release publishes it last.
  `.github/workflows/release.yml` publishes them on a tag of a commit of `main` or `release/X.Y` once ci.yml's run of
  that branch's push is green on it (or on the commit after it, the next version): PyPI, npm, ghcr.io and a GitHub
  release, each file built once in a job that can't publish. The workflows run on
  GitHub's runners (`ubuntu-latest`)
- `demo/` — the recording at the top of the README (`demo.gif`): `record.sh` runs `demo.tape` in a terminal
  recorder in a container, on the guide's own app (`files.py` takes it from `docs/getting-started.md`); made
  again by hand when what the commands print changes, and at each release (`RELEASING.md`; `Demo` in
  `unit_test.py` checks the tape still fits)
- `.github/workflows/ci.yml` — on each pull request and push to `main` or `release/X.Y`: `tests/unit_test.py` and the type checks
  (`unit`), the suites (`suites.yml`, called once per version: every suite on PG 16, `ci.sh`, and what depends on
  the version on 17 and 18, `ci.sh --short`), what they run of the code (`coverage`: on a pull request, a line or
  branch it changes in `authzlib` or `cli` that no suite runs fails it, and on any run PL/pgSQL never run other
  than `core/tests/plpgsql_floor.txt` says), the review, the examples, the conformance suites, the editors,
  packaging, the playground, Studio's page and the site. Every job has a `timeout-minutes`
  (about three times its longest run, ten at least), so a step that hangs fails soon. The suites run in parts, a
  job each, side by side (`ROWSTILE_PART`; `run_tests.sh` names them and puts each step in one: a new step goes in
  a unit inside an `if part ...` (a function, then `unit PART SECONDS NAME`: a part's units run in lanes,
  `tests/lanes.sh`), and a new part in the workflows' lists, which `Delivery` in `unit_test.py` checks); the jobs
  `postgres (16)`, `postgres (17, --short)` and `postgres (18, --short)` only wait for their version's parts.
  `main` requires them by name in the repository's ruleset, with `coverage` and every other job of ci.yml but the parts: a new job
  is added there by hand. `nightly.yml` (main; by hand, one job: `-f only=<job>`) — the full run on 16 in its
  parts side by side (`races` among them), every suite on 17 and 18 (with upgrades from every release from the
  beta on), the proofs (`--proofs`) on 17 and 18 (on 16 the full run's `races` runs them), the soak (new seeds
  each night, one version in turn, in six parts side by side; by hand, several at once on the three versions:
  `gh workflow run nightly.yml -f only=soak -f soaks=7`), the conformance suites on 17 and 18 and on 16 through
  PgBouncer (`integrations/pooler.sh`), the migrations `rowstile migrate` writes run by goose, dbmate, Flyway and
  Django (`tests/migration_tools.sh`), the grammar and the parser on every small policy, the fuzzer, the
  comparison pages' readings (`readings`), and the benchmark check (`-f only=bench`; it judges speed against the
  runners' own baseline, not the gate's limits). By hand alone, the figures the limits page quotes: `-f
  only=speed` (`benchmark.sql`) and `-f only=scale -f size=large` (the scale benchmark at one of `scale.sh`'s
  sizes; the gate's speed limits shown, not judged; with `--ref <branch> -f against=main`, that commit and the
  branch in turn on the one runner, `core/bench/compare.sh`). `ci.sh` writes its logs to `/tmp`
- `.github/workflows/scorecard.yml` — the OpenSSF Scorecard, weekly and on `main`: published at scorecard.dev
  (the README's badge), each check's reason in the run's files, the findings under Security, Code scanning.
  Publishing restricts the workflow: only its listed actions, no `run` steps, no `env`

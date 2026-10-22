# Contributing

Thank you for helping. rowstile decides who may read and change which rows, so a change is held to one bar:
it must say what it does, and a test must show it. This page says how a change gets in. How to run the
suites is in [core/README.md](core/README.md). A security problem goes to [SECURITY.md](SECURITY.md), not an
issue. Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).

## Before you start

- **A bug**: open an issue with the smallest policy, schema and steps that show it, what happened, and what
  should have. A pull request with the fix is welcome right away.
- **Anything new users would see**: a change to the policy language, a new `authz.*` function, a new command
  or flag, a new SDK surface. Open an issue first and say what problem it solves. These are design decisions,
  and a pull request is the wrong place to make them. It saves you work that might not be merged.
- **Docs, typos, small fixes**: a pull request is enough.

## Branches

`main` is the only long-lived branch. It is always green and always releasable. Work on a short-lived branch
from `main`, named for what it does (`fix-move-under-self`, `docs-drizzle-page`); outside contributors, on a
fork. A big change lands as several pull requests, each leaving `main` working. Branches are deleted once
merged.

Patches for an older release are made on `release/X.Y`, only when one is needed ([RELEASING.md](RELEASING.md)).
Fixes go to `main` first, then to the release branch.

## What a change needs

- **A check in the suite that would have caught it.** Every change of behaviour gets one, in the suite that
  covers it (the table in [core/README.md](core/README.md)). A bug fix says why that suite missed it.
- **The generated SQL, on purpose.** A change to what the compiler writes shows up in `core/tests/golden/`:
  run `python3 core/tests/unit_test.py --update` and read the diff before you commit it.
- **The docs.** If users see the change, the page that describes it says so. Code in the docs is tested
  (`docs/getting-started.md`, the cookbook, the stack pages, the reference), so it must still run. A promise
  on the reference's pages, the threat model or the page on how rowstile is checked (a sentence that says
  always, never, can't, only, refuses, keeps or removes) ends with a comment naming the check that holds it, or
  saying why none does: `Promises` in `core/tests/unit_test.py` says how.
- **A line in [CHANGELOG.md](CHANGELOG.md)** under **Unreleased**, if users will notice: under Added, Changed,
  Fixed or Upgrading (what someone upgrading must do). A check asks for it when a pull request changes what
  users run; a maintainer adds the label `no changelog` when they won't notice.
- **Types and layout.** Every Python function says its arguments' and result's types, the code passes ty and
  Ruff, and Ruff lays it out (`uvx ruff@0.15.12 format` before you commit; 120 columns). A pre-commit hook
  refuses staged Python that isn't laid out; turn it on once in your clone with
  `git config core.hooksPath .githooks`. The commits that only changed the layout are listed in
  `.git-blame-ignore-revs`: `git config blame.ignoreRevsFile .git-blame-ignore-revs` makes `git blame` skip
  them (GitHub does already). The checks CI runs:
  `uvx ty@0.0.56 check && uvx ruff@0.15.12 check && uvx ruff@0.15.12 format --check`, from the repository's
  root (`ty.toml`, `ruff.toml`); code that needs packages in its own
  environment: `uv sync --project integrations/fastapi && uvx ty@0.0.56 check --project sdk/python` (and
  `--project` integrations/fastapi, examples/filemanager, examples/messenger after syncing their backends). The
  command's code uses the standard library only, annotations included. TypeScript is `strict`, and so is the
  plain JavaScript (Studio's page, the playground, the site, the npm scripts, the editors): typed with JSDoc and
  checked by `npx tsc -p <folder>` (the `tsconfig.json` beside it; Studio's is `core/cli/tsconfig.studio.json`).
- **Plain words** in messages and docs: short sentences, the names users know (`core/CONTEXT.md`). An error a
  policy can cause names the policy line and has a code with its own page (`core/authzlib/errors.py`).

The project's conventions (how the SQL is generated, locking, sessions, what must stay re-appliable) are in
[CLAUDE.md](CLAUDE.md). It is written for coding agents and reads well for people too.

## Commits

- **Each commit says what changed**, in the subject line, in plain words ("Moves under a folder's own
  descendant are refused", not "fix bug"). The body says why, if it isn't obvious.
- **Sign off each commit**: `git commit -s` adds `Signed-off-by: Your Name <you@example.com>`. It says you
  may submit the change under the project's license (Apache-2.0), as the
  [Developer Certificate of Origin](https://developercertificate.org/) puts it. A check refuses a pull request
  with a commit that isn't signed off. For commits already made: `git rebase --signoff main`.
- Everything is LF. A new script starting with `#!` is executable in git (`git update-index --chmod=+x`).

## Pull requests

- CI must be green: the unit tests and the type checks, every suite on PostgreSQL 16 and what depends on the
  version on 17 and 18, the SDKs' conformance suites, the example apps, the editors, the packaging, the
  playground and the site. The rest runs each night on `main`: every suite on 17 and 18, the proofs, the
  soak and the benchmark check. On each pull request, `rowstile review` says what it does to the file
  manager's policy (`examples/filemanager`): "unchanged" when it doesn't touch it.
- **Review**: a maintainer reviews each outside pull request, and may push small fixes to your branch.
  Expect questions about the tests more than about the code.
- **Merging**: a maintainer merges. An outside pull request is squashed into one commit, and the maintainer
  writes its message from your description, keeping your authorship and sign-off. A maintainer's own pull
  requests are rebased as they are (their commits each say what changed). A merge commit is used only when a
  commit must stay reachable, as when the Zed extension pins its grammar to a commit.
- Keep your branch up to date by rebasing on `main`, not by merging `main` into it.

## Versions and releases

One version covers everything a release ships: the command, the Python package, the TypeScript packages and
the image. Between releases `main` says `X.Y.Z-dev`, the version it is heading for. How releases are numbered
and made, and what a 0.x release may change: [RELEASING.md](RELEASING.md).

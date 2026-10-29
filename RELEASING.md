# Releasing

How rowstile is numbered and released. For maintainers; [CONTRIBUTING.md](CONTRIBUTING.md) is how a change
gets into `main`.

## Versions

rowstile follows [semantic versioning](https://semver.org/). One version covers everything a release ships:
the `rowstile` command, the Python package, the TypeScript packages (`@rowstile/*` and the command's
platform packages), the image, and the review for CI. `packaging/version.py` sets it in every file but the
install lines that name the image's tag (the release pull request edits those), and a unit test fails if two
files disagree. The editor extensions (VS Code, Zed) have their own versions, raised
when they change: the Marketplace takes no alphas, betas or release candidates. A release publishes the VS Code extension
on the Marketplace and Open VSX when its version isn't there yet, each once its token is set (`VSCE_PAT`,
`OVSX_PAT`, in the environment `vscode`). `VSCE_PAT` isn't set: a new version goes to the Marketplace by hand,
the release's `.vsix` uploaded on the publisher's page (marketplace.visualstudio.com/manage/publishers/rowstile).
Zed's is by hand too: a pull request to zed-industries/extensions that moves the `extensions/rowstile` submodule
to the release's commit and sets the same version in `extensions.toml`.

| version | what it is | published |
|---|---|---|
| `0.2.0` | a minor release. Before 1.0 it may change the language, the `authz.*` functions, the SDKs and the file formats, and the changelog's **Upgrading** says what to do | `latest` |
| `0.2.1` | a patch: fixes only, nothing to do when upgrading | `latest` |
| `0.2.0-alpha.1` | an alpha of 0.2.0 (PyPI: `0.2.0a1`): for trying it early. It may have known gaps, and anything in it may still change before 0.2.0 | npm's `next` (and `latest` while no final release exists), a GitHub pre-release; never the image's `latest` |
| `0.2.0-beta.1` | a beta of 0.2.0 (PyPI: `0.2.0b1`): the version complete enough to use before it is released. It may still change where using it shows a need | npm's `next` (and `latest` while no final release exists), a GitHub pre-release; never the image's `latest` |
| `0.2.0-rc.1` | a release candidate for 0.2.0 (PyPI: `0.2.0rc1`): meant to become 0.2.0 as it is | npm's `next` (and `latest` while no final release exists), a GitHub pre-release; never the image's `latest` |
| `0.2.0-dev` | `main` between releases, on its way to 0.2.0 (PyPI: `0.2.0.dev0`) | never: the release workflow refuses it |

An alpha, a beta or a candidate is installed by asking for it: `npm i rowstile@next`, `pip install --pre
rowstile` (or `rowstile==0.2.0b1`), the image by its version. A version's alphas come before its betas, its
betas before its candidates, and the command orders them so: `0.2.0-alpha.2`, then `0.2.0-beta.1`, then
`0.2.0-rc.1`, then `0.2.0` (`core/authzlib/versions.py`, the one grammar `packaging/version.py`, the downgrade
guard, `rowstile init` and the upgrade test read).

Every release from `0.1.0-beta.1` on upgrades from the one before it, and that is tested: `core/tests/upgrade.sh`
installs the newest release on PyPI older than the checkout's version, and upgrades databases it made. The beta
started afresh: the alphas before it are never the release before (`FIRST` in `core/tests/previous_release.py`),
and until a release from the beta on is older than the checkout's version, the suite says there is nothing to
upgrade from and skips (the beta's own release, and `main` until the beta is on PyPI). Every night, `upgrade.sh
--every` does so from each release on PyPI from the beta on, with a world of data whose answers after the upgrade
must be a new database's: before a release, the last night's run passed (or run it on the release's commit:
`ROWSTILE_PART=command ROWSTILE_UPGRADES=every core/ci.sh 16`). What 1.0 promises beyond that is decided
before 1.0.

A build from `main` records its version with a hash of the compiler's sources (`0.2.0-dev+3f2a9c1e8b7d`), so
`rowstile apply` never takes a database applied by one build as up to date for another.

## The cycle

- **A minor release when it is ready**: when `main` holds something worth releasing. Once a month, check
  whether `main` has sat on unreleased changes.
- **Alphas when there is something to try early**: `alpha.1`, `alpha.2` and on, before the version's first
  beta or candidate and never after it. An alpha is released like a candidate (below) and promises less: it
  says what is there, not that it is done.
- **Betas when the version is complete enough to use**: `beta.1`, `beta.2` and on, after its alphas and before
  its first candidate, never after it. A beta is released like a candidate (below).
- **Release candidates before each minor and major release**: `rc.1`, then `rc.2` and on if fixes land. Each
  is installed from the registries the way users install it and checked before the next step. The final
  release is the last candidate with only the version and the changelog changed (its own section, above the
  candidate's).
- **Patches whenever a fix is ready**, tagged straight from a green `main` or `release/X.Y`, without a
  candidate: an urgent fix shouldn't wait a round.

## Tags and branches

- Tags are `vX.Y.Z`, `vX.Y.Z-alpha.N`, `vX.Y.Z-beta.N` and `vX.Y.Z-rc.N`, annotated, on a commit of `main` or `release/X.Y` whose version files
  say that version (the release workflow checks both: a tag on another branch's commit publishes nothing). A
  tag is never moved or deleted once pushed: a bad release is followed by a new one.
- A patch comes from `main` when `main` holds only fixes since the last release. Otherwise, make
  `release/X.Y` from the tag `vX.Y.Z` (once), land the fix on `main` first, then cherry-pick it to the branch
  (`git cherry-pick -x`) in a pull request, and release from there.

## The changelog

[CHANGELOG.md](CHANGELOG.md) is what a release's notes are made from, and the site shows it as a page. Its
layout, which `Delivery` in `core/tests/unit_test.py` checks (`layout()` in `packaging/changelog.py`):

- `## Unreleased` first: what `main` holds since the last release. Each pull request users will notice adds its
  line there ([CONTRIBUTING.md](CONTRIBUTING.md)).
- Then a section for each release, newest first, headed with its exact version and its day:
  `## 0.2.0-alpha.1 (YYYY-MM-DD)`, `## 0.2.0-beta.1 (...)`, `## 0.2.0-rc.1 (...)`, `## 0.2.0 (...)`. A
  release's notes on GitHub are its section alone, never the version's whole history.
- In a section, its parts in this order, each once at most: `### Added`, `### Changed`, `### Removed`,
  `### Fixed`, `### Upgrading` (what someone upgrading from the release before must do: a policy line to rewrite,
  a call to rename, a migration to make; only there, never inside another part's line). A short paragraph may
  come before the first part.
- A part's lines are a list, one line a change, with no blank line inside it. A line says what users see, in
  plain words; what they won't notice belongs in the commit message.
- A link to a file of the repository is written from its root, as GitHub reads this file:
  `[Installing](docs/installing.md)`. A release's notes get it as a link to that file at the release's tag
  (`changelog.py` writes it so), since a release's page reads a relative link from its own address.
- Last, `## Before the beta`: what the alphas were, and a link to each one's GitHub release, which keeps its
  notes.

## Making a release

First, the Python the npm packages bring. It is python-build-standalone's, pinned by hand in
`packaging/npm/build.mjs` (`RELEASE`, `PYTHON` and a SHA-256 for each platform), and Dependabot doesn't watch it:
a fix in CPython or OpenSSL reaches npm users only when it moves. When the newest release
(`gh release view -R astral-sh/python-build-standalone --json tagName`) is newer than `RELEASE`, move to it in a
pull request of its own, before the release's (the comment above `RELEASE` says what changes with it).

Then the demo at the top of the README (`demo/demo.gif`): record it again from `main` with `demo/record.sh`
([demo/README.md](demo/README.md)). If what the commands print has changed, land the new recording in a pull
request of its own, before the release's.

1. **The release pull request**, from a branch `release-X.Y.Z` (or `release-X.Y.Z-rc.N`, `release-X.Y.Z-beta.N`,
   `release-X.Y.Z-alpha.N`), with two commits:
   1. the release itself, with the subject line `X.Y.Z-rc.N` (or `X.Y.Z-alpha.N`, `X.Y.Z-beta.N`, `X.Y.Z`):
      - `python3 packaging/version.py X.Y.Z-rc.N`
      - the install lines that name the image's tag, `ghcr.io/rowstile/rowstile:X.Y.Z-rc.N`, in `README.md` and
        `docs/installing.md`: version.py leaves them, and the unit tests (`DocPages`) fail until they name it
      - `CHANGELOG.md`: **Unreleased** becomes the release's own section, `## X.Y.Z-rc.N (YYYY-MM-DD)` (the
        day of the tag), with a new empty `## Unreleased` above it. Every release has one, an alpha, a beta or a
        candidate as much as a final release, and its notes are that section alone
        (`python3 packaging/changelog.py X.Y.Z-rc.N` prints them). A final release's section opens with a
        sentence saying which candidate it is and that its alphas', betas' and candidates' sections below hold
        what changed since the release before; under it, what changed since that candidate, if anything
      - the apps' migrations, where `rowstile migrate --check` asks for one: in `examples/filemanager`,
        `examples/messenger`, `integrations/fastapi` and `integrations/nextjs`, run
        `python3 ../../core/cli/rowstile_cli.py migrate --name rowstile_X_Y_Z`. This is the upgrade users
        will make, run by CI on each app
      - `python3 core/tests/docs_app.py --sync`: the release records its own docs app
        (`core/tests/docs_apps/releases.txt`, from `0.1.0-beta.1` on: the beta's release is the first line), which
        `tests/upgrade.sh` upgrades it with later; without it the release run's unit tests, which have the tags,
        fail on the release's own tag (as 0.1.0-alpha.8's did)
   2. `main`'s next version: `python3 packaging/version.py X.(Y+1).0-dev` after a final release,
      `X.Y.Z-dev` after an alpha, a beta or a candidate, with the subject line that version.
2. **Merge it** with a rebase once CI is green, so both commits land on `main` as they are.
3. **Tag the first commit** and push the tag:

       git fetch origin
       sha=$(git log origin/main --format=%H -1 --grep '^X.Y.Z-rc.N$')
       git tag -a vX.Y.Z-rc.N -m "rowstile X.Y.Z-rc.N" "$sha"
       git push origin vX.Y.Z-rc.N

4. **The release workflow** (`.github/workflows/release.yml`) runs on the tag. It checks that the tag and the
   version agree and that the tag's commit is on `main` or `release/X.Y`, runs the unit tests and the packaging
   tests, then publishes: the Python package, the npm packages, the image, and a GitHub release holding the
   wheel, the sdist, the npm launcher and the VS Code extension, with the changelog's section as its notes.
   Each file is built once, in a job with no right to publish, and PyPI and the Marketplace get the files the
   GitHub release attaches. Last, the MCP server's entry in the official registry (`server.json`): that
   registry is a preview, and a failure there never fails the release (run the `mcp` job again). A patch to an
   older line moves no `latest`: not npm's, the image's or GitHub's. An alpha, a beta or a candidate goes under
   npm's `next`; while no final release exists the run then moves npm's `latest` there too, so a plain `npm i
   rowstile` gets the newest (`packaging/npm_latest.py`). It waits for the registry to show the release
   first, up to twenty minutes: npm shows a publish some minutes late, and a package it still doesn't show
   is named, for the by-hand run below. Moving the tag needs **Allow npm dist-tag** ticked in each
   package's trusted publisher on npmjs.com: where it isn't, the run says which packages and the release
   stands. The tag also deploys the docs site at
   rowstile.dev (`.github/workflows/site.yml`), built from its commit, when that commit is on `main` and no
   site tag is on a later one (below).
5. **Check it** as a user would: install from the registries on Linux, then `rowstile init`, `migrate` and
   `test` on a small app, and the review action on a pull request. Then the next alpha, beta or candidate, or
   the final release. A tag pushed is not a release made: look at the workflow's run, and at what it
   published. macOS and Windows are not checked this way: there is no machine or runner with either. What
   checks them is the release's packaging tests (`packaging/test.sh`), which read their npm packages (the
   Python is built for that system and CPU, and holds every library and module the command loads) but can't
   start them; the Linux ones, x64 and arm64, glibc and musl, are started.

Run by hand (Actions, **release**, **Run workflow**), the release workflow builds and checks everything and
publishes nothing: a dry run before tagging. From `main`, a `-dev` version, the notes it writes are what
**Unreleased** holds.

Run by hand with `latest`, it does one thing instead: npm's `latest` goes where `next` is on every package,
and nothing is published. It is for a release whose own run couldn't move it, and moves nothing once a final
release exists:

    python3 packaging/npm_latest.py              # what it would move, read from the registry
    gh workflow run release.yml -f latest=true   # moves it, from main

## The site

The site, rowstile.dev, doesn't wait for a release: its code, the home page, the docs, the blog, the comparison
pages and the playground are all built from one commit of `main`. A **site tag** deploys them:

    git fetch origin
    git tag -a site-vN -m "the site, N" origin/main
    git push origin site-vN

- Site tags are `site-v1`, `site-v2` and on: a plain count, annotated, on a commit of `main`, and like a
  release's never moved or deleted once pushed. A wrong page is followed by the next tag.
- The site workflow (`.github/workflows/site.yml`) builds the whole site from the tag's commit and deploys it.
  The site's links to files in the repository go to that tag.
- The docs then say what `main` says: between releases, the reference and the guide may describe a change
  that isn't on PyPI or npm yet. Tag the site when that is what it should show.
- A release's tag on `main` deploys the site too, from its own commit: a release needs no site tag. A tag
  pushed on a commit older than another such tag's (a release made from an earlier commit, after a site tag)
  deploys nothing, and a release's tag off `main` (a patch to an older line) neither: the site never goes back
  by itself. To put it back on purpose, run it by hand: `gh workflow run site.yml -f tag=site-vN` deploys
  that tag, whatever comes after it.
- `site/source.mjs` holds the rule and `site/source_test.mjs` checks it; `node site/source.mjs site-vN` says
  whether a tag deploys.
- The release workflow doesn't run on a site tag, which publishes no package (`Delivery` in
  `core/tests/unit_test.py` checks that no pattern of its own matches one).
- What the comparison pages say of other projects is quoted from their documentation, with the day it was
  read, and wants reading again each quarter. `python3 docs/compare_readings.py` lists each page's reading
  and the day it is due again, and the nightly's `readings` job fails once one is past it. Read the
  documentation again from its sources, correct what changed, write the new day, and publish the pages with
  a site tag.

## The repository's settings

Dependabot is on: its monthly, grouped updates (`.github/dependabot.yml`) and its security updates (the
repository's settings, Code security). **Private vulnerability reporting** is on there too, since the repository
went public: [SECURITY.md](SECURITY.md) sends reports there.

## Security releases

A vulnerability reported privately ([SECURITY.md](SECURITY.md)) is fixed in the GitHub security advisory's
private fork, released as a patch (while no final release exists, as the next pre-release: there is no
release to patch), and the advisory is published with the release, crediting the reporter if
they want it.

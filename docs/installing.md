# Installing

rowstile is a command, `rowstile`, and an SDK for your app's language. Nothing is installed in the database:
the command writes migrations, and your migration tool runs them as the owner of your tables. Any PostgreSQL
16, 17 or 18 works, managed or not.

## The command

Only pre-releases are published so far. Ask for the newest:

    npm i -D rowstile@next         # the command with its own Python: a TypeScript app needs none
    pip install --pre rowstile     # the command and the Python SDK: rowstile[fastapi], [sqlalchemy], ...
    docker run --rm -u "$(id -u):$(id -g)" -v "$PWD:/work" ghcr.io/rowstile/rowstile:0.1.0-alpha.9 migrate

Once 0.1.0 is out, the plain `npm i -D rowstile`, `pip install rowstile` and `ghcr.io/rowstile/rowstile` get
it. Until then a plain `npm i -D rowstile` and `pip install rowstile` get the newest pre-release too (npm's
`latest` follows `next` while no final release exists, and pip takes a version that isn't final when no final
one exists), but the image has no `latest` tag: name its version.

- **npm**: the package brings a Python of its own, built for your machine: Linux (glibc and musl, x64 and
  arm64), macOS (x64 and arm64) and Windows x64. Run it as `npx rowstile`, or from a script in `package.json`.
  It needs Node 22.12 or newer, as the TypeScript SDK does. On another platform, or with optional dependencies
  turned off (that Python is one), it runs on a Python 3.11 or newer found on `PATH`.
  `ROWSTILE_PYTHON=/path/to/python3` names the Python to run on instead: 3.11 or newer, or the command says so
  and stops.
- **pip**: Python 3.11 or newer. The same package is the [Python SDK](../sdk/python/README.md), and its extras
  bring what each part of it uses: `rowstile[fastapi]`, `rowstile[sqlalchemy]`, `rowstile[psycopg]`,
  `rowstile[asyncpg]`. The command needs none of them.
- **Docker**: the image holds the command and git (`rowstile review` asks git for the base branch's files),
  and works in the folder mounted at `/work`. It is built for Linux on x64 and arm64: Docker takes the one for
  your machine, an Apple Silicon Mac's the arm64 one. It runs as root unless told otherwise: `-u` makes the
  files it writes yours. Its label `org.opencontainers.image.version` says its version.

`rowstile --version` says which version runs, and on which Python.

## Alphas, betas and release candidates

Once a final release exists, a plain install gets it, never a version that isn't final. Ask for one:

    npm i -D rowstile@next
    pip install --pre rowstile

and the image by its version (`ghcr.io/rowstile/rowstile:0.2.0-rc.1`). An alpha is for trying a version
early: anything in it may still change. A beta (`0.2.0-beta.1`, on PyPI `0.2.0b1`) is the version complete
enough to use before it is released: it may still change where using it shows a need. A release candidate is
meant to become the release as it is.
[The changelog](../CHANGELOG.md) says what each version changed, and under **Upgrading** what to do when
moving to it.

## Checking a download

Each package says where it was built, signed through Sigstore by the release workflow that built it: npm shows
its provenance on the package's page (`npm audit signatures` checks it), and PyPI its attestations. The files
on a [GitHub release](https://github.com/rowstile/rowstile/releases) (the wheel, the sdist, the launcher, the
editor extension) come with `rowstile-<version>.intoto.jsonl`, from 0.1.0-alpha.9 on.
The GitHub CLI checks a file against it (the wheel's name writes the version as Python does: `0.1.0b1` for
`0.1.0-beta.1`):

    gh attestation verify rowstile-<version>-py3-none-any.whl --repo rowstile/rowstile

## From the repository

    git clone https://github.com/rowstile/rowstile
    export PATH="$PWD/rowstile/core/cli:$PATH"

The command is Python 3.11 or newer and its standard library: there is nothing else to install.

## Then

`rowstile init` finds the stack (Next.js, Prisma, Drizzle, FastAPI, SQLAlchemy, Alembic, goose, dbmate,
Flyway), writes `rowstile.toml` for its migration tool, adds the SDK's packages to `package.json` (for Python,
names the one to add) and says which line to change.

- [Getting started](getting-started.md): from a schema to a policy, its tests, the edit loop and the first
  migration.
- [Your stack](stacks/README.md): the SDK's packages for it ([Python](../sdk/python/README.md),
  [TypeScript](../sdk/typescript/README.md)), and where each line goes.
- [Editors](../editor/README.md): highlighting and the language server for VS Code, Zed, Helix and Neovim.

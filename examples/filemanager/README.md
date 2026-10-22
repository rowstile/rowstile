# File manager

A file-sharing app built on rowstile: folders, files, and sharing them with people, groups and links. FastAPI
backend, React frontend, Postgres governed by rowstile, and RustFS (S3-compatible) for the file contents.

It uses rowstile like any outside adopter:
its own policy (`db/policy.authz`), applied from its own migrations, and only the public surface
(the `rowstile` command, `authz.*` functions and settings, the generated Python client). `check_public_surface.py` enforces
that, and CI runs it against the rowstile image built from the same commit.

## Running it

    docker compose up -d --build        # Postgres + rowstile, RustFS, the app: http://localhost:8000

Create an account on the sign-in page (open sign-up is on by default: `FM_OPEN_SIGNUP=false` turns it
off). To work on it, the services in Docker and the rest on the host:

    docker compose up -d --wait db storage      # the services only (Postgres on 25432, RustFS on 29000)
    export FM_ADMIN_URL=postgresql://postgres:postgres@localhost:25432/filemanager FM_APP_PASSWORD=fm_app
    export FM_DATABASE_URL=postgresql://fm_app:fm_app@localhost:25432/filemanager FM_S3_ENDPOINT=http://localhost:29000
    cd backend
    uv run python ../db/migrate.py --client     # the migrations, as the tables' owner, and the client
    uv run uvicorn app.main:app --reload        # the API on http://localhost:8000, as fm_app

and in another terminal, `cd frontend && npm ci && npm run dev`: the web app on `http://localhost:5173`, which
sends `/api` to the backend. The tests, from this folder:

    ./test.sh                           # the tests: public surface, client up to date, API against the real services

## How it fits together

| | |
|---|---|
| `db/migrations/` | the tables (`fm.users`, `fm.groups`, `fm.folders`, `fm.files`, ...), the app role's grants, and the policy's migrations, which `rowstile migrate` writes from `db/policy.authz` |
| `db/policy.authz` | who may do what: folders nest and pass access down unless a folder stops it; sharing with people and groups (nested), with expiry; editors may change a folder, but moving, deleting or sharing it, or stopping inheritance, takes the right to share it; support staff may break the glass |
| `db/migrate.py` | runs the migrations not run yet, and with `--client` rewrites `backend/app/authz_client.py` (`rowstile client py`) |
| `backend/app/main.py` | the HTTP API. Every call runs in a transaction signed in as the user (`authz.user_id`), so row-level security decides what it sees and changes; the backend adds no permission checks of its own (one exception: listing and revoking share links, a table of the app's, ask `authz.can` first). At start it refuses a connection that skips row-level security (`authz.connection_check()`) |
| `backend/app/storage.py` | file contents in RustFS. A download link is signed only after the file's row was read through row-level security, and lives 10 minutes. A browser uploads to a place of its own; confirming the upload moves the bytes to the file's object, so the upload link can't change a confirmed file |
| `frontend/` | the web app (see Features) |

Things a user may not see answer 404, as if they didn't exist; asking for access to one doesn't reveal
whether it does.

## Features

Folders and files; upload (straight from the browser to RustFS) and download (signed links); sharing
with people and groups, with expiry; share links anyone can open without signing in, listed and turned
off in the share dialog; who has access and why; moving; stopping inheritance on a folder; groups run
in the app (owners, admins, sub-groups; anyone may leave); search by name; access requests and
reviews; break glass for support staff; file versions (every upload over a file is kept, any can be
made current again, and the database refuses to point a file at an object that isn't one of its own
versions); previews in the browser (images, PDF, text, audio, video; anything else, HTML above all, is
only downloaded); storage quotas per person, enforced by the database (every version counts).

## Not yet

Thumbnails, full-text search, and quotas per group.

A folder can't be deleted while it holds something, also something its owner can't see: an editor may make
a folder inside and stop inheritance on it, and the owner of the folder above then gets "the folder isn't
empty" until that editor removes theirs. The foreign key says so whoever asks (rowstile's threat model, "Side
channels"); deleting hidden things on the owner's word would be a rule of the app's own to write.

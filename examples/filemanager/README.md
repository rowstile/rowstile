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
    (cd frontend && npm ci && npm test) # the web app's tests, against a fake API

## Running it for longer

Compose runs no maintenance. Run the jobs on a schedule (cron, a Kubernetes CronJob), say once an hour, as the
tables' owner. With compose, from this folder:

    docker compose exec app python -m app.maintenance    # or, on the host: cd backend && uv run python -m app.maintenance

They remove uploads that never finished (their rows and objects, after a day: `--uploads-older-than` says
otherwise), what is left in the uploads' place in storage after a day, and sessions that ended; and they trim
rowstile's change feed to its last 7 days (`authz.trim_changes()`). The audit trail is kept: trim it with
`authz.trim_audit(...)` once you have decided how long to keep it.

The settings, from the environment:

| Setting | Default | |
|---|---|---|
| `FM_DATABASE_URL` | `postgresql://fm_app:fm_app@localhost:5432/filemanager` | the app's connection, as `fm_app`: the app refuses to start on one that skips row-level security |
| `FM_ADMIN_URL` | none | the tables' owner (or a superuser), for `db/migrate.py`, the maintenance jobs and `rowstile.toml` |
| `FM_APP_PASSWORD` | none | `fm_app`'s password, which `db/migrate.py` sets (it makes the role if it is missing) |
| `FM_S3_ENDPOINT` | `http://localhost:9000` | where the backend reaches the storage |
| `FM_S3_PUBLIC_ENDPOINT` | `FM_S3_ENDPOINT` | where browsers reach it: signed links point there |
| `FM_S3_BUCKET` | `files` | the bucket, made at start if it is missing |
| `FM_S3_ACCESS_KEY` | `rustfsadmin` | the storage's credentials (RustFS's defaults: change them on both sides) |
| `FM_S3_SECRET_KEY` | `rustfsadmin` | |
| `FM_S3_REGION` | `us-east-1` | |
| `FM_WEB_ORIGINS` | `http://localhost:8000,http://localhost:5173` | where the web app is served from, comma-separated: the app puts them in the bucket's CORS rule at start, so browsers there may upload straight to storage |
| `FM_COOKIE_SECURE` | `false` | `true` as soon as it is served over HTTPS: the session cookie then goes over HTTPS only |
| `FM_OPEN_SIGNUP` | `true` | anyone may create an account; `false`: the sign-up page refuses, and accounts are made in the database by its owner |
| `FM_SESSION_DAYS` | `14` | how long a session lasts |
| `FM_MAX_UPLOAD_BYTES` | `1073741824` | the largest file (1 GiB): checked when an upload starts, and again on what arrived |
| `FM_LINK_MINUTES` | `10` | how long a signed download or upload link works |

## How it fits together

| | |
|---|---|
| `db/migrations/` | the tables (`fm.users`, `fm.groups`, `fm.folders`, `fm.files`, ...), the app role's grants, and the policy's migrations, which `rowstile migrate` writes from `db/policy.authz` |
| `db/policy.authz` | who may do what: folders nest and pass access down unless a folder stops it; sharing with people and groups (nested), with expiry; editors may change a folder, but moving, deleting or sharing it, or stopping inheritance, takes the right to share it; support staff may break the glass |
| `db/tests/` | the policy's own tests, each with its own people and folders, rolled back after it: `rowstile test` runs them |
| `rowstile.toml` | what `rowstile test` and `rowstile migrate` read: the policy, its tests, the migrations' folder, and the database (`FM_ADMIN_URL`) |
| `db/migrate.py` | runs the migrations not run yet, and with `--client` rewrites `backend/app/authz_client.py` (`rowstile client py`) |
| `backend/app/main.py` | the HTTP API. Every call runs in a transaction signed in as the user (`authz.user_id`), so row-level security decides what it sees and changes; the backend adds no permission checks of its own. Where it asks rowstile whether the user may do something (`authz.can`, `authz.list`, `authz.perms`), it is only to tell the web app what to offer: each listed folder's and file's `can_edit` and `can_share`, a group's `manage`. At start it refuses a connection that skips row-level security (`authz.connection_check()`) |
| `backend/app/auth.py` | accounts and sessions: passwords hashed with scrypt, a session cookie whose hash is in `fm.sessions`. The backend checks them, then tells the database who is asking |
| `backend/app/db.py` | the transactions signed in as the user, or as nobody with a share link's token (the generated client's `sign_in` and `use_links`) |
| `backend/app/authz_client.py` | the client `rowstile client py` writes from the policy (`db/migrate.py --client`): never edited by hand |
| `backend/app/storage.py` | file contents in RustFS. A download link is signed only after the file's row was read through row-level security, and lives 10 minutes (`FM_LINK_MINUTES`). A browser uploads to a place of its own; confirming the upload moves the bytes to the file's object, so the upload link can't change a confirmed file |
| `backend/app/maintenance.py` | the jobs to run on a schedule (Running it for longer) |
| `backend/app/config.py` | the settings (Running it for longer) |
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

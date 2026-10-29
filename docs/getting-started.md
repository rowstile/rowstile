# Getting started

From an empty folder to access rules enforced by Postgres, tested, in about fifteen minutes. You need a
Postgres (Docker runs one below) and the `rowstile` command. (This guide runs as written in the tests:
`core/tests/docs_test.sh`.)

## 1. Postgres with rowstile

rowstile needs nothing installed in the database: any PostgreSQL 16, 17 or 18 will do. [Install the
command](installing.md), start a Postgres, and say where it is:

    pip install --pre rowstile     # or: npm i -D rowstile@next, and write npx rowstile below
    docker run -d --name pga -e POSTGRES_PASSWORD=secret -p 5432:5432 postgres:18
    export DATABASE_URL=postgresql://postgres:secret@localhost:5432/postgres

Or, in a clone of the repository, from its root: the image the tests use (the stock Postgres 16, or 17, 18
with `PG_MAJOR`, and the command in it) and the command as it is in the repository:

    docker build -t rowstile:16 --build-arg PG_MAJOR=16 -f core/Dockerfile .
    docker run -d --name pga -e POSTGRES_PASSWORD=secret -p 5432:5432 rowstile:16
    export PATH="$PWD/core/cli:$PATH"                              # the rowstile command
    export DATABASE_URL=postgresql://postgres:secret@localhost:5432/postgres

The `rowstile` command compiles your policy and applies plain SQL, connected as the owner of your tables
(`DATABASE_URL`; here the `postgres` user). Your app will connect as its own role. Work in an empty folder
from here on. For SQL, `docker exec -it pga psql -U postgres`.

## 2. Your tables, and the role your app connects as

rowstile governs tables you already have. A small example:

```sql
CREATE SCHEMA app;
CREATE TABLE app.users (id bigint PRIMARY KEY, name text);
CREATE TABLE app.teams (id bigint PRIMARY KEY, name text);
CREATE TABLE app.team_members (team_id bigint REFERENCES app.teams, user_id bigint REFERENCES app.users,
                               PRIMARY KEY (team_id, user_id));
CREATE TABLE app.projects (id bigserial PRIMARY KEY, owner_id bigint NOT NULL REFERENCES app.users, name text);
CREATE TABLE app.notes (id bigserial PRIMARY KEY, project_id bigint NOT NULL REFERENCES app.projects,
                        author_id bigint NOT NULL REFERENCES app.users, body text);
CREATE INDEX ON app.team_members (user_id);     -- the columns the rules will look rows up by
CREATE INDEX ON app.projects (owner_id);        -- (rowstile dev names the ones that are missing)
CREATE INDEX ON app.notes (project_id);
CREATE INDEX ON app.notes (author_id);

CREATE ROLE app_backend LOGIN PASSWORD 'change me' NOSUPERUSER NOBYPASSRLS;   -- the role your app connects as
GRANT USAGE ON SCHEMA app TO app_backend;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO app_backend;
GRANT INSERT, UPDATE, DELETE ON app.projects, app.notes TO app_backend;   -- the tables the policy governs
GRANT USAGE ON ALL SEQUENCES IN SCHEMA app TO app_backend;

INSERT INTO app.users VALUES (1, 'ada'), (2, 'bo'), (3, 'cy');
INSERT INTO app.teams VALUES (10, 'writers');
INSERT INTO app.team_members VALUES (10, 2);
INSERT INTO app.projects (owner_id, name) VALUES (1, 'Novel');
INSERT INTO app.notes (project_id, author_id, body) VALUES (1, 1, 'Chapter one');
```

## 3. A first draft: `rowstile init`

```sh
rowstile init --schema app --role app_backend
```

It reads your tables and foreign keys and writes three files: `db/policy.authz` (a policy that compiles),
`db/tests/first.authz` (a first test) and `rowstile.toml` (where things are, for the other commands).
It also leaves a short note in `AGENTS.md`, for coding agents that work in the project: where the policy
is, and the loop.
Tables became types, foreign keys became relations (`owner_id` is `owner : user = owner_id`; `project_id`
is `project : project = project_id`, and a note inherits view and edit from its project), and
`app.team_members` became `member : user = app.team_members(team_id -> user_id)` on teams. Every line
marked `-- decide:` is a choice only you can make.

Here, projects are shared: people give others access with `authz.share()`, if they hold `share` on the project
(`shared` is short for `shared by share`, which the cookbook writes out). And only the tables the app
writes need rules, where the draft has a type and rules for every table, the link table
`app.team_members` too. Replace the draft with this:

```authz db/policy.authz
app role app_backend

type user = app.users

type team = app.teams
  member : user = app.team_members(team_id -> user_id)

type project = app.projects
  owner  : user = owner_id
  editor : user, team#member shared  -- people share projects with authz.share()
  viewer : user, team#member shared

  can share = owner
  can edit  = share or editor
  can view  = edit or viewer

type note = app.notes
  project : project = project_id
  author  : user    = author_id

  can edit = author or project.edit
  can view = edit or project.view

rules app.projects
  select          : view
  insert          : owner
  update          : edit
  update owner_id : share
  delete          : share

rules app.notes
  select                  : view
  insert                  : project.edit and author
  update                  : edit
  update project_id after : project.edit   -- the project it moves to (the row after the change)
  update author_id        : project.share  -- or anyone who may edit could make themselves the author
  delete                  : edit
```

`shared` relations hold what people give each other with `authz.share()`; who may give them is the type's
`can share`. The layout is `rowstile fmt`'s: run it on your own files, and `rowstile fmt --check` in CI.

With an editor that speaks the Language Server Protocol, mistakes show while you type, and hovering
`project.edit` shows what it means (`editor/README.md`).

## 4. Tests that bring their own data

A test sets up the rows it needs, checks what people may do, and is rolled back. `$name` is what a
`given` returned:

```authz db/tests/first.authz
test "a project's owner and editors write notes; nobody else sees them"
  given ada = {INSERT INTO app.users VALUES (101, 'ada') RETURNING id}
  given bo = {INSERT INTO app.users VALUES (102, 'bo') RETURNING id}
  given cy = {INSERT INTO app.users VALUES (103, 'cy') RETURNING id}
  given p = {INSERT INTO app.projects (owner_id, name) VALUES ($ada, 'Novel') RETURNING id}
  given n = {INSERT INTO app.notes (project_id, author_id, body) VALUES ($p, $ada, 'Chapter one') RETURNING id}

  user $ada can edit note $n
  user $cy cannot view note $n
  as user $cy sees 0 {SELECT FROM app.notes WHERE project_id = $p}
  as user $bo refused {INSERT INTO app.notes (project_id, author_id, body) VALUES ($p, $bo, 'mine')}
  as user $ada allowed {SELECT authz.share('project', $p, 'editor', 'user', $bo)}
  as user $bo allowed {INSERT INTO app.notes (project_id, author_id, body) VALUES ($p, $bo, 'mine')}
  user $bo cannot share project $p
```

`user X can PERM TYPE ID` asks the policy. `as user X allowed|refused|sees N {SQL}` runs the statement as
your app's role, signed in as X, so it tests row-level security itself.

## 5. The edit loop: `rowstile dev`

```sh
rowstile dev --once
```

Without `--once`, it watches the policy and the tests. On every save it checks the policy, shows who would
gain or lose access, applies it, runs the tests and writes your clients:

```text
rowstile dev: db/policy.authz -> postgres on localhost:5432
10:04:31 start
  ok   compiles
  ok   applied in 0.12 s (the whole policy)
  ok   7 check(s) pass; 7 branches no "can" check reaches (line 13: owner, line 14: share, ...)
```

The last line counts the branches of the policy no test makes true yet (`rowstile test --coverage` lists
them). From the second run on, a line says who gains or loses access (`~    access: nobody gains or loses
anything`), and a lookup that no index serves is named, with the index to add.

A mistake stops it before anything is applied (`db/policy.authz: line 14: project has no relation or
permission 'edtor' (it has: edit, editor, owner, share, view, viewer) [AZ203]`), and a failing check prints
why, from the database. Every mistake ends with its code: `rowstile help AZ203` says what it means and shows
it fixed (`docs/errors/`).

## 6. Ask as a user

Every transaction starts by saying who is asking, with `authz.act_as`, then plain SQL is filtered by
row-level security. The sign-in is signed and lasts one transaction, so the app can't change it later by
setting `authz.user_id`, and a transaction that forgets it gets an error, not an empty page.

Those two hold for a connection that logs in as the app role, as your app's will. The session below is
`postgres`'s, switched to the app role with `SET ROLE`: handy for trying things, but a superuser's or the
owner's session is believed without a signature (it could `RESET ROLE` anyway), so in it a forgotten
sign-in reads as nobody and returns no rows. `SELECT * FROM authz.connection_check()` lists what is wrong
with a connection for an app: a row for `postgres`'s (a superuser's), none for one that logs in as the app
role. The rules themselves apply in both once the role is the app's:

```sql
SET ROLE app_backend;
BEGIN;
SELECT authz.act_as('user', '3');                   -- cy
SELECT * FROM app.notes;                            -- nothing
COMMIT;

BEGIN;
SELECT authz.act_as('user', '1');                   -- ada shares the project with the writers team
SELECT authz.share('project', 1, 'editor', 'team', 10, 'member');
COMMIT;

BEGIN;
SELECT authz.act_as('user', '2');                   -- bo is a writer
SELECT * FROM app.notes;                            -- Chapter one
UPDATE app.notes SET body = 'Chapter one, again';   -- allowed: he may edit the project
SELECT authz.can('project', 1, 'share');            -- false
SELECT * FROM authz.explain('project', 1, 'share'); -- why not
COMMIT;
RESET ROLE;
```

When the database refuses a write, the error says which rule refused it and why. Here cy, who has no access
to the project, adds a note to it (`INSERT INTO app.notes (project_id, author_id, body) VALUES (1, 3, 'mine')`):

```text
ERROR:  permission denied: user 3 may not insert this row into app.notes
DETAIL:  no   insert : project.edit and author  (line 33)
  no   project.edit
    no   you have no access to project 1
  yes  author
```

The same from a terminal, as anyone, without writing anything:

```sh
rowstile explain-rule --as user:3 app.notes insert --row '{"project_id": 1, "author_id": 3}'
rowstile sql --as user:2 "SELECT id, body FROM app.notes"
```

## 7. From your app

`rowstile.toml` can name clients to write on every change (`[clients] py = "app/authz_client.py"`), or:
`rowstile client py > authz_client.py` (or `ts`). Commit it next to your code. The example connects with
[psycopg](https://www.psycopg.org) (`pip install "psycopg[binary]"`); `current_user_id`, `project_id`,
`note_id` and `body` are your request's.

```python
import psycopg
from authz_client import Authz, NotFound, Refused, refusal

with psycopg.connect("postgresql://app_backend:change%20me@localhost/postgres") as conn:
    with conn.transaction():
        az = Authz(conn)
        az.sign_in(current_user_id)                          # authz.act_as('user', ...)
        notes = conn.execute("SELECT id, body FROM app.notes WHERE project_id = %s", (project_id,)).fetchall()
        # an UPDATE that changed nothing: NotFound (you can't see it) or Refused (you may not, and why)
        row = conn.execute("UPDATE app.notes SET body = %s WHERE id = %s RETURNING id", (body, note_id)).fetchone()
        az.expect(row, "app.notes", "update", note_id)

# in your web framework's error handler: a refused write is a 403 with the database's reason
def on_error(e):
    r = refusal(e) if not isinstance(e, Refused) else e
    if r:
        return 403, {"detail": "you may not do that", "why": r.why}
    if isinstance(e, NotFound):
        return 404, {"detail": "not found"}
```

Keep every request in one transaction that starts with `sign_in`: the setting ends with the
transaction, so a pooled connection never carries one user's identity into another's request.

No Python in your app? [Plain SQL, from any language](stacks/sql.md) has the same in the statements
themselves, and [your stack](stacks/README.md) has an SDK that does it for you.

## 8. Ship it: migrations

`rowstile dev` applies straight to your development database. Production takes the policy as
migrations, written for the tool your app already uses (`alembic`, `prisma`, `drizzle`, `sql`, `goose`,
`dbmate`, `flyway` or `django`). Name it in `rowstile.toml`, then write the first one:

```sh
printf '[migrations]\ntool = "sql"\ndir = "migrations"\n' >> rowstile.toml
rowstile migrate
```

```text
  the whole policy (29 lines)
wrote migrations/20261003120000_authz_policy.sql
wrote db/policy.lock
wrote .gitattributes (reviews show the generated files collapsed)
```

Commit all three. From then on each change to the policy is the next migration, holding only what
changed, not the whole policy again, and starting with what changed, as comments.
`rowstile dev`, left watching, writes it some minutes after your last save; after `rowstile dev --once`,
or whenever you want it now, `rowstile migrate` does. `rowstile migrate --check` in CI fails a policy
change that has no migration. Deploy them as you deploy the others: there is no extra step. With plain SQL
files, each runs in one transaction: `psql -1 -v ON_ERROR_STOP=1 -f migrations/<file>.sql`.

## Next

- [Your stack](stacks/README.md): FastAPI, Next.js, Node, Python, or plain SQL from any language.
- [The cookbook](cookbook.md): recipes (tenants, teams, folders that inherit, sharing, denies, bots,
  blocking...), each tested.
- [Troubleshooting](troubleshooting.md): what people run into, by symptom.
- The reference: [the language](reference/language.md), [every function](reference/app-code.md) and
  [every command](reference/tools.md).
- [The messenger](../examples/messenger/README.md) and [the file manager](../examples/filemanager/README.md):
  complete apps with no permission checks in their backends.
- [Running rowstile](operations.md): upgrading, backups, retention, monitoring.

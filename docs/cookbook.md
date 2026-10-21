# Cookbook

Recipes for common access rules. Each has a page of its own, with the policy lines, what each does and a
test, and a folder under `docs/cookbook/` with its own small tables (`schema.sql`), a few rows (`rows.sql`),
policy (`policy.authz`), tests (`tests.authz`) and `rowstile.toml`. CI applies and tests every one, and checks
that every line of policy and tests a page shows is in those files (`core/tests/cookbook.sh`). Each page links
to the playground, where the recipe runs in your browser, or
[try it on a database of your own](#trying-a-recipe-on-your-own-database).

The language in one breath: a **type** is a table; a **relation** says who or what a row is linked to (a
column, a link table, or shares people make); a **permission** combines relations with `or`, `and`, `not`,
`rel.perm` (follow a relation) and `{SQL}`; **rules** say what each command on a table needs.

## Rows and their owners

- [Rows only their owner can see and change](cookbook/owner-only.md): a relation read from a column.
- [Let each user edit only their own row](cookbook/your-own-row.md): a relation read from the row's own key.

## Groups and trees

- [Nested groups: teams inside teams](cookbook/teams-inside-teams.md): members of sub-teams count, to any
  depth.
- [Folder permissions that inherit down a tree, and stop where a folder says so](cookbook/folders-that-inherit.md):
  `parent.edit`, moves, `and {inherit}`.
- [Hiding a page and everything under it](cookbook/deny-that-inherits.md): `and not`, a deny that inherits.

## Sharing

- [Sharing a row with a person or a team, for a while, and share links](cookbook/sharing-and-links.md):
  `shared by share`, `authz.share()`, `authz.create_link()`.
- [Sharing like Google Docs: private, shared with people, anyone with the link, public](cookbook/google-docs-sharing.md):
  a `visibility` column beside shares and links.
- [Access on request: ask, approve, and it ends by itself](cookbook/access-on-request.md):
  `authz.request_access()`, `authz.decide_request()`.
- [Who has access to this row, why, and who gave it](cookbook/who-has-access.md): `authz.who()`,
  `authz.list_shares()`, `authz.explain()`.

## Tenants and roles

- [Multi-tenant row-level security: organisations, workspaces, projects](cookbook/multi-tenant-app.md): the
  tenant reached through the rows, and an invariant proved.
- [Tenant isolation, with keys of two columns](cookbook/tenants.md): every row in its organisation, admins
  and members.
- [Admin, member and guest roles per organisation, and roles the admins make](cookbook/roles-per-organization.md):
  roles from a column, and custom roles.

## Rules on the row, and who writes

- [Rules that depend on the row: read-only announcement channels](cookbook/conditions-on-the-row.md): `{SQL}`
  conditions.
- [Soft-deleted and archived rows: read-only archives, and a trash the owner restores from](cookbook/archived-and-deleted.md):
  conditions for a row's state.
- [Hiding a column from some users: a masked salary](cookbook/hiding-a-column.md): a masked view.
- [Letting support staff see what a user sees, and emergency access](cookbook/support-and-emergency-access.md):
  `authz.view_as()`, `authz.break_glass()`.
- [Permissions for services and bots, not only users](cookbook/bots-and-services.md): principals with their
  own API keys.
- [API keys limited to some permissions](cookbook/api-keys-with-scopes.md): scopes, and tests that check a
  line as a key would be.
- [Blocking a user: nobody writes to someone who blocked them](cookbook/blocking.md): following a relation to
  a person.

## Live updates: who to tell

When a row changes, a backend that pushes updates asks once which of its connected people may see it:

```sql
SELECT * FROM authz.who_among('channel', '7', 'read', ARRAY['1', '2', '3']);
```

It signs each one in with `authz.act_as`, so it is for whoever may call that: the app role, a backend trusted to
sign people in.
The messenger does this (`examples/messenger/backend/app/events.py`): its WebSocket carries only "chat 7 changed", and
the browser refetches through the API.

## Signing in, when the tables are under row-level security

Checking a password reads a table before anyone is signed in. Keep credentials in a table the policy doesn't
govern, and read them through a `SECURITY DEFINER` function the app role may call
(`examples/messenger/db/migrations/0001_schema.sql`: `ms.credentials_for`). `authz.lint()` notes such functions:
check each only reads what it must.

## Trying a recipe on your own database

Each recipe's folder has a `rowstile.toml` that names its policy and its tests, so `rowstile dev` finds them.
In a copy of the folder, with [rowstile installed](installing.md):

```sh
createdb owner_only
psql -d owner_only -f schema.sql -f rows.sql
DATABASE_URL=postgresql://localhost/owner_only rowstile dev
```

- `schema.sql` makes the recipe's tables, in the schema `app`, and the app role, `app_user`, that the app connects as.
  Run it as a Postgres user that may create roles. That user owns the tables, and `rowstile dev` connects as
  it too. Each recipe wants a database of its own.
- `rows.sql` adds a few rows to ask about, the ones the playground shows. The tests bring their own.
- `rowstile dev` applies the policy and runs the tests, then does it again each time you save one of them.
  `rowstile dev --once` does it once and stops.

CI takes these steps for every recipe, with `--once` (`core/tests/cookbook.sh`).

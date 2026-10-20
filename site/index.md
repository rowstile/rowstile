---
layout: home
hero:
  name: rowstile
  text: Access rules for Postgres
  tagline: Authorization inside your Postgres. Sharing, groups and nested folders in one policy file, compiled to row-level security. No second service, no data to sync.
  actions:
    - theme: brand
      text: Get started
      link: /getting-started
    - theme: alt
      text: Try it in the browser
      link: /playground/
      target: _self
    - theme: alt
      text: Reference
      link: /reference/language
features:
  - title: No second system
    details: The rules read the tables your app already has. Relations come from your own columns and link tables, permissions are built from them and inherited down trees of folders or teams. Nothing to copy into an authorization service and keep in step.
  - title: Enforced by Postgres
    details: Row-level security filters every read and checks every write. The app signs in each transaction and queries its tables as usual. A refused write says which rule and why.
  - title: A change you can review
    details: Tests next to the policy, invariants checked in many small worlds, and on each pull request a review that says who gains or loses access.
  - title: Plain SQL, shipped as migrations
    details: Each change to the policy is a migration for the tool your app already uses (Alembic, Prisma, Drizzle Kit, SQL, goose, dbmate, Flyway). Any Postgres 16, 17 or 18. No extension, no superuser, and what lands in the database is SQL you can read.
---

## A small policy

```authz
app role app_user                               -- the Postgres role the app connects as
type user = app.users
type folder = app.folders
  owner  : user   = owner_id                    -- a relation read from a column
  parent : folder = parent_id
  editor : user   = app.folder_editors(folder_id -> user_id)   -- ... or from a link table
  can edit = owner or editor or parent.edit     -- inherited down the tree
  can view = edit
rules app.folders
  select : view
  update : edit
```

The app says who is asking, then runs its usual queries:

```sql
BEGIN;
SELECT authz.act_as('user', '42');
SELECT * FROM app.folders;                      -- only the folders 42 may view
UPDATE app.folders SET name = 'Plans' WHERE id = 7;   -- 0 rows unless 42 may edit folder 7
COMMIT;
```

The SDKs turn a write that changed nothing into a 404 (the row can't be seen) or a 403 that says which rule
refused it and why.

## Is it for you?

It fits when your app's data is in one Postgres database, and who may see or change a row depends on other
rows: its owner, the members of a team (teams inside teams), a folder or a project that passes access down, a
tenant, what people share with each other. It is for you if you were about to add an authorization service and
keep it in step with the database, or if your hand-written row-level security has become hard to test and to
change.

It doesn't fit when what decides access is in several databases or outside Postgres, when a browser reads the
tables through Supabase's Data API, or when one tree takes many moves and links a second. And if you need an
outside audit or a vendor behind it today: rowstile is a 0.x preview with one maintainer, and
[nobody outside has audited it](../docs/reference/guarantees.md#security).

Next: [Getting started](../docs/getting-started.md) goes from a schema to a policy, its tests, the edit loop and
the first migration. [Pick your stack](../docs/stacks/README.md) for the SDK that does the signing in for you.

For coding agents: each page here is also Markdown, at its address with `.md` (<https://rowstile.dev/getting-started.md>),
and <https://rowstile.dev/llms.txt> lists them with what to know first.

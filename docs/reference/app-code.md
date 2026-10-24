# Using it from app code

Python apps use [the Python SDK](../../sdk/python/README.md): `Rowstile(app, engine, user=...)` for FastAPI, `install(engine)` for
SQLAlchemy, and transactions for psycopg and asyncpg sign each transaction in, turn refusals into 403 and
hidden rows into 404, and check the app's connection at start-up. `integrations/fastapi` is its conformance
suite. TypeScript apps use [the TypeScript SDK](../../sdk/typescript/README.md): `@rowstile/prisma` (a driver adapter that signs every
transaction in, and a client extension), `/pg`, `/postgres` (postgres.js), `/drizzle`, `/next` (signed-in reads
kept out of caches, 403 and 404 from route handlers and server actions), `/react` (`usePerms`, `<Can>`, a
headless share dialog, live updates) and `/vitest`; `integrations/nextjs` is their conformance suite, and
`rowstile client` writes only the policy's names for them (`src/authz.gen.ts`). <!-- checked: tests/unit_test.py "test_typescript_sdk_gets_only_the_names" -->
The SDK's calls (`calls(q)`, and each driver's: Prisma's `db.$authz`) are `can`, `perms`, `permsOf`, `list`,
`listShares`, `share`, `unshare`, `requestAccess`, `explainRule`, `connectionCheck` and `expect` (and Prisma's
`ids`). Its `share` takes no expiry, start or caveat. For those, and for the rest of the table below (`who`, `explain`, links,
requests, reviews, keys), call the `authz.*` function in SQL.
Underneath, and for every
other stack:

Everything is a SQL function in schema `authz`, callable by the app role, acting as
the signed-in user. Ids are text or the type's key type. A composite key's id is the text
Postgres writes for the row: `authz.can('folder', '(1,42)', 'view')`, or from SQL
`ROW(f.org_id, f.id)::text`; `authz.list` returns ids in that form (`'(1,"a b")'` for a text
column that needs quoting), and the generated clients take a tuple or array.

| task | function |
|---|---|
| check, list, all permissions | `authz.can('file', 11, 'edit')`, `authz.list('folder', 'edit')`, `authz.perms('file', 11)` |
| all permissions on many objects (a list's buttons) | `authz.perms_of('file', ARRAY['10', '11'])`: a row per id, `id` and `perms` |
| list in pages, in key order | `authz.list('file', 'view', NULL, 1000)`, then `authz.list('file', 'view', '<last id>', 1000)` (a NULL size: no limit; a cursor that isn't an id, or a negative size: AZ710) |
| who has access (for people who may share it) | `authz.who('folder', 3, 'view')` |
| why, or what is missing | `authz.explain('file', 11, 'edit')`; for someone else (people who may share it, as for `who`): `..., 'edit', '7')` |
| why a write is or would be refused | `authz.explain_rule('app.files', 'update', '11', '{"name": "x"}')`: NULL if the row isn't there or you can't see it (404); an insert: `authz.explain_rule('app.files', 'insert', NULL, '{"folder_id": 6}')` <!-- checked: tests/devx.sh "a row that isn't there: NULL (404, not 403)"; tests/devx.sh "and one the user can't see: NULL too"; tests/devx.sh "an update that would be allowed: yes" --> |
| which of these people may see it (live updates) | `authz.who_among('file', 11, 'view', ARRAY['1', '2'])`: it signs each one in with `authz.act_as`, so it is for whoever may call that (the app role, a backend trusted to sign people in) |
| the sharing dialog | `authz.list_shares('folder', 3)`, for people who may share it: a row a share, with `relation`, `role` (a custom role's name), `subject_type`, `subject_id` (`(link)` for a share link), `subject_relation` (`member` for `team#member`, else empty), `expires_at`, `starts_at`, `caveat`, `created_by` and `created_at` |
| share and unshare | `authz.share('file', 13, 'viewer', 'user', 4, '', now() + interval '1 day')` (then when it starts, a caveat and its arguments: [the language](language.md)), `authz.unshare(...)` |
| share links | `authz.create_link('folder', 3, 'viewer')` returns a token; requests use it with `SET LOCAL authz_ctx.links = '<token>'` |
| an object's links, and turning one off | `authz.list_links('folder', 3)`: each link's id, relation, who made it, when, and until when, for people who can share the object or may make such links; `authz.revoke_link('folder', 3, '<id>')` turns one off, and needs what unsharing its relation needs (the id is not the token, and opens nothing; an id that names no link there: AZ708); a link given in several relations is judged in each as things are before it goes, and goes from all of them or from none <!-- checked: tests/governance.sh "a link in two relations, which its token lets user 1 share: turned off in both"; tests/governance.sh "turned off in neither" --> |
| custom roles | `authz.create_role('org', 1, 'folder', 'reviewer', ARRAY['view'])` returns the role's id (needs `manage_roles` on the org); share it as `authz.share('folder', 3, 'role:<id>', 'user', 7)`; `authz.set_role_permissions(id, ARRAY[...])`, `authz.delete_role(id)`, `authz.roles_of('org', 1)`; for users, not services (AZ715) <!-- checked: tests/principals.sh "authz.create_role is for users: a service is told so"; tests/principals.sh "authz.set_role_permissions is for users: a service is told so"; tests/principals.sh "authz.delete_role is for users: a service is told so"; tests/principals.sh "authz.roles_of is for users: a service is told so" --> |
| API keys | `authz.create_api_key('laptop', 'read')` (shown once), `authz.list_api_keys()`, `authz.revoke_api_key(id)`; a service's keys are made by a user holding `manage_keys` on it ([Identity](identity.md)), and a service making its own is refused (AZ715) <!-- checked: tests/principals.sh "authz.create_api_key for oneself is for users: a service is told so"; tests/principals.sh "its owner makes service 7 a key" --> |
| sign in | `authz.login_key('ak_...')`, `authz.login_jwt('eyJ...')` (HS256; settings in `authz.settings`) |
| the app's connection, at start-up | `authz.connection_check()`: a row per problem, `severity` and `problem` ([Checking the database](governance.md#checking-the-database)) |
| support "view as" | `authz.view_as('42', 'ticket 1234')`: read-only, audited, needs `can impersonate` on the user; for users, not services (AZ715) <!-- checked: tests/principals.sh "authz.view_as is for users: a service is told so"; tests/identity.sh "and cannot change anything"; tests/identity.sh "the audit trail has the reason"; tests/identity.sh "carol cannot view as erin" -->. In a session limited by scopes (an API key's, a token's) it keeps them, and never reads more than they give <!-- checked: tests/identity.sh "a key that may only view as someone"; tests/identity.sh "one with files too" --> |
| ask for access | `authz.request_access('folder', 3, 'viewer', 'for the audit', '7 days')`, `authz.cancel_request(id)`; for users, not services (AZ715) <!-- checked: tests/principals.sh "authz.request_access is for users: a service is told so"; tests/principals.sh "authz.cancel_request is for users: a service is told so" --> |
| decide requests | `authz.pending_requests()`, `authz.decide_request(id, true, 'ok')`: approving makes a share that ends after the requested time; for users, not services (AZ715) <!-- checked: tests/principals.sh "authz.pending_requests is for users: a service is told so"; tests/principals.sh "authz.decide_request is for users: a service is told so" --> |
| emergency access | `authz.break_glass('folder', 6, 'viewer', 'INC-7 outage', '1 hour')`: needs `break_glass`, one day at most, audited, announced on channel `authz_alerts`; for users, not services (AZ715) <!-- checked: tests/principals.sh "authz.break_glass is for users: a service is told so" --> |
| access reviews | `authz.start_review('folder', 3)`, `authz.review_items(id)`, `authz.review_decide(id, item, false)`, `authz.close_review(id)`; for users, not services (AZ715) <!-- checked: tests/principals.sh "authz.start_review is for users: a service is told so"; tests/principals.sh "authz.review_items is for users: a service is told so"; tests/principals.sh "authz.review_decide is for users: a service is told so"; tests/principals.sh "authz.close_review is for users: a service is told so" --> |

Administrators (the policy's owner and superusers; the app role is refused) also have: <!-- checked: tests/governance.sh "the app role cannot run lint"; tests/governance.sh "the app role cannot trim"; tests/governance.sh "the app role cannot run the invariant check"; tests/identity.sh "the app role cannot sync" -->

| task | function |
|---|---|
| inheritance tables match a rebuild | `authz.verify()` |
| the change feed (for caches, search indexes, sync jobs) | poll `authz.changes_since(pos)` ([where to start](governance.md)); `LISTEN authz_changes` only after `INSERT INTO authz.settings VALUES ('notify_changes', 'on')` (every notifying commit waits its turn) <!-- checked: tests/governance.sh "by default the feed doesn't NOTIFY (it would queue every commit): consumers poll"; tests/governance.sh "with notify_changes on, listeners hear of a change (NOTIFY authz_changes)" --> |
| the audit trail | `SELECT * FROM authz.audit` (append-only; every share, unshare, role, membership change, request, review, break-glass, view-as, API key) <!-- checked: tests/governance.sh "the trail cannot be edited, even by an administrator"; tests/governance.sh "a share is recorded, with who made it"; tests/governance.sh "memberships kept in your tables are recorded too"; tests/multi_scenario.sql "the audit trail has the roles made"; tests/governance.sh "the audit trail has the requests, their answers and the reviews"; tests/governance.sh "the trail has it, with the reason"; tests/identity.sh "the audit trail has the reason"; tests/identity.sh "the audit trail has the keys made and the one revoked" --> |
| retention (schedule these: pg_cron, or the app's jobs) | `authz.trim_changes()` keeps 7 days of the feed (or the setting `changes_keep`); `authz.trim_audit(interval '2 years')` removes older audit entries and records that it did <!-- checked: tests/governance.sh "the feed keeps 7 days by default: older entries are trimmed"; tests/governance.sh "how long the feed keeps entries is a setting"; tests/governance.sh "older ones go"; tests/governance.sh "and the trim is recorded" --> |
| group sync from an identity provider | `authz.sync_members('team', '10', 'member', ARRAY['1', '2'])` makes the group's rows in the relation's table (`app.team_members`) this list: it deletes and inserts there. For a relation read from one table, without `where`; shares are not touched. An empty list removes every member; a NULL list, or a NULL in it, is refused (AZ710). <!-- checked: tests/identity.sh "an empty list removes every member"; tests/identity.sh "a NULL list is refused"; tests/identity.sh "... and a list with a NULL in it" --> |
| invariants | `authz.check_invariants()` |
| ways around RLS | `authz.lint()`: see [Checking the database](governance.md#checking-the-database) |

Generated clients wrap these with the policy's names, so a typo in a permission is a
compile error: `rowstile client py > authz_client.py`
(DB-API: psycopg and friends) or `rowstile client ts > authz.ts` (TypeScript, for `pg` or
anything with `query(text, params)`). Generate it from the policy in force and commit it next to
your code; regenerate when the policy changes (the file manager's tests fail when it is stale).

- **Python: supported.** Part of the 1.0 surface: `Authz(conn)`, with `sign_in`, `sign_in_as` (a principal
  other than a user), `principal`, `connection_check`, `can`, `list` (with `after` and `limit` for pages), `perms`,
  `who`, `explain`, `share` (its `caveat_args` a dict), `unshare`, `list_shares`, `create_link`, `list_links`,
  `revoke_link`, `use_links`, `request_access`, `decide_request`, `cancel_request`, `pending_requests`,
  `break_glass`, `start_review`, `review_items`, `review_decide`, `close_review`, `login_key`, `login_jwt`,
  `create_api_key`, `list_api_keys`, `revoke_api_key`, `explain_rule`, `expect` and `who_among`; the errors
  `Refused` (`.table`, `.command`, `.why`) and `NotFound`, with `refusal(error)` turning a driver's
  error into a `Refused`; and the policy's names as types: `ObjectType`, `Permission`, and each type's own,
  `FilePermission` for `file` (the type's name with a capital first letter; two types that would get the same
  name, `doc` and `Doc`, get none). Rows come back as dicts. The file manager and the messenger use it.

**Refusals say why.** A write the rules refuse raises SQLSTATE 42501 with the rule and what is
missing, as the signed-in user may know it (nothing about rows they can't see): <!-- checked: tests/devx.sh "a refused insert says which rule, and which part of it"; tests/devx.sh "and says nothing about a folder the user can't see"; tests/adversarial.sh "a write refused in a hidden folder explains as for a missing one"; tests/reference.sh "the refusal app-code.md shows is the docs app's, word for word" -->

```
ERROR:  permission denied: user 1 may not insert this row into app.files
DETAIL:  no   insert : folder.edit and owner  (line 80)
  yes  folder.edit
  no   owner
```

The error's table, schema and constraint (`authz_insert`, `authz_update`) fields are set, which is what
`refusal(error)` reads. <!-- checked: tests/devx.sh "with the table and the policy in the error's fields" -->
An allowed write never runs this (the check is `rule OR refuse(row)`). <!-- checked: tests/devx.sh "an allowed update is not refused" -->
Updates
and deletes the rules don't allow change no rows instead (row-level security leaves them out):
`az.expect(result, table, command, id)` then raises `NotFound` or `Refused` with `authz.explain_rule`'s
answer, worded like the refused insert above: `permission denied: user 3 may not update row 11 of
app.files`. <!-- checked: tests/adversarial.sh "updating a hidden row changes nothing"; tests/tools_test.py "expect, a row the user may not change: Refused, with why"; tests/tools_test.py "worded as the database words a refused insert: who, the command, the row, the table" -->
A key of several columns is written as the database writes it, `(1,2)`. <!-- checked: tests/tools_test.py "a key in a message is as the database writes it: quoted only where Postgres would" -->
- **TypeScript: preview.** `asUser(db, id, fn)` and `asPrincipal(db, type, id, fn)` run `fn` in a transaction
  signed in (Python's `sign_in` and `sign_in_as`). `authz(db)` has `can`, `connectionCheck`, `list`, `perms`,
  `who`, `explain`, `share` (its options in an object: `subjectRelation`, `expiresAt`, `startsAt`, `caveat`,
  `caveatArgs`), `unshare`, `listShares`, `createLink`, `listLinks`, `revokeLink`, `useLinks`, `requestAccess`,
  `decideRequest`, `cancelRequest`, `pendingRequests`, `breakGlass`, `startReview`, `reviewItems`,
  `reviewDecide`, `closeReview`, `loginKey`, `loginJwt`, `createApiKey`, `listApiKeys`, `revokeApiKey`,
  `explainRule`, `expect` and `whoAmong`: Python's calls in camelCase, except `principal`. It also has
  `Refused`, `NotFound` and `refusal(e)`, and the types `ObjectType` and `Permission<T>`. It may change before
  it is supported.

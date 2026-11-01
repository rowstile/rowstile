# The sync index (a preview)

Sync engines (Electric, Zero, PowerSync) read Postgres by logical replication, then decide on their own servers
which rows each client gets. Row-level security doesn't run on that path, so an engine has to be told the rules
again. The sync index tells it: for each row of a synced table, the keys that may read it, kept in tables the engine
replicates like any other, in the same transaction as the change. <!-- checked: tests/sync.sh "a share made: frank reads file 13"; tests/sync.sh "a transaction rolled back changes nothing in the index" -->

This is a preview. Its lines, tables and functions may change in any release, and it is outside what 1.0 will
promise. [Electric](#electric) runs on it, behind the app's own server; Zero and PowerSync come later.

## Declaring it

<!-- not run: applying needs the sync engine's role; tests/sync.sh applies this policy, the docs app's with these lines -->
```authz
sync role sync_engine        -- the engine's Postgres role
sync app.files : view        -- each file's readers hold view on it
sync app.folders             -- no permission: the table's select rule
```

Two words change the way the index is worked out, not what it says:

<!-- not run: tests/sync.sh applies these lines to the docs app, in its sections "keyed by folder" and "after commit" -->
```authz
sync app.files : view by folder   -- a file's readers name its folder's key, which its readers hold
sync after commit                 -- a worker keeps the index after each change commits
```

- `sync role` names the role the engine connects as. Make it for the engine: `CREATE ROLE sync_engine LOGIN
  REPLICATION BYPASSRLS`. It can't be the app role or PUBLIC (AZ803). <!-- checked: tests/policy_errors.py "the app role as the sync role"; tests/policy_errors.py "PUBLIC as the sync role" -->
  Applying refuses a role that isn't there, one that is a member of the app role or has it as a member, and one
  that is a member of the role applying the policy (AZ808). <!-- checked: tests/sync.sh "a sync role that isn't there is refused"; tests/sync.sh "a sync role that is a member of the app role is refused"; tests/sync.sh "... and so is one the app role is a member of"; tests/sync.sh "... and so is one that is a member of the policy's owner" -->
- `sync schema.table : permission` names a type's table, one line each, and the permission its readers hold. With
  no permission, they hold the table's select rule, which the table must have (AZ801). <!-- checked: tests/policy_errors.py "a sync line naming no permission, for a table without a select rule"; tests/policy_errors.py "a sync line naming a permission its type hasn't" -->
- Sync lines need a sync role, and a sync role needs a sync line (AZ802). <!-- checked: tests/policy_errors.py "sync lines and no sync role"; tests/policy_errors.py "a sync role and nothing synced" -->
  So does `sync after commit`. <!-- checked: tests/policy_errors.py "sync after commit and nothing synced" -->
- `by folder`, on a sync line, keys its readers by a type's inheritance ([Keyed by folder](#keyed-by-folder)).
- `sync after commit`, once in the policy, has a worker keep the index ([After commit](#after-commit)).

## Its tables

Applying makes the schema `authz_sync`. The sync role may read it, and nobody else may: not the app role, nor
PUBLIC. <!-- checked: tests/sync.sh "the app role can't read the index"; tests/sync.sh "the sync role reads the index, and nothing else of rowstile's" -->
Every table there has `REPLICA IDENTITY FULL`, which Electric asks for. <!-- checked: tests/sync.sh "every table of the index has REPLICA IDENTITY FULL, as Electric asks" -->

| table | what it holds |
|---|---|
| `<type>__readers` | for each row: the type's key columns (typed as its key), and `key`, a key that may read it |
| `keys` | `principal_type`, `principal_id`, `key`: for each principal, the keys it holds |
| `groups` | `grp`, `key`: the keys that make up a group's key |
| `expanded` | `object_type`, `object_id`, `key`: what a row's readers were worked out from, where they are principals |
| `definitions` | what the index was worked out by, so that applying knows whether to work it out again |
| `pending` | where the policy says `sync after commit`: the objects each committed change reached, which the worker hasn't worked in yet |

A key is one of these:

- a principal: `user:42`, `service:7`;
- every signed-in principal of a type: `user:*`;
- `anyone`;
- a group: the holders of a relation or permission of a group's object, `team#member:10` or `org#admin:1`;
- keyed by folder, the holders of a permission that inherits, on one object: `folder#view:7`.

A principal holds its own key, its type's `user:*`, `anyone`, and the keys of the groups it is in, through groups
inside groups. <!-- checked: tests/sync.sh "an org admin holds the org's group key, and a team's member its team's and the teams it sits in"; tests/sync.sh "a new user holds keys: their own, every user's, anyone's, and their team's" -->
`principal_id` is the principal's own id, and `principal_type` its type. A principal that has no row, or fails its
type's `where`, holds no key: it is nobody, and the index gives it nothing. <!-- checked: tests/sync.sh "a user deleted: their keys go" -->

The rows a principal may read are those whose readers hold one of its keys. An engine filters with that one join
(Electric's `where`, set by the app's proxy, with the signed-in user's id):

<!-- not run: it reads the index, which the docs app the reference runs on doesn't keep; tests/sync.sh asks it of every user -->
```sql
SELECT id FROM app.files
WHERE id IN (SELECT r.id FROM authz_sync.file__readers r
             WHERE r.key IN (SELECT k.key FROM authz_sync.keys k
                             WHERE k.principal_type = 'user' AND k.principal_id = '42'))
```

For every principal with a row, those are the rows `authz.list` gives it, without what comes only through a caveat
or a link (below). <!-- checked: tests/sync.sh "applied: for every user, the index holds what authz.list gives (files, and folders by their select rule)"; tests/difftest.py "the sync index: " -->

### How readers are worked out

From the permission's expression, as the compiler reads it:

- a relation gives its subjects' keys: a column (`owner_id`), a link table, shares that have started and not ended;
- a group named as a subject (`team#member`) gives its key, not its members: a member joining or leaving changes
  their keys, not the readers of what the group is given; <!-- checked: tests/sync.sh "... and the files' readers didn't change: only bob's keys did"; tests/sync.sh "a share to a group is one key on the folder, not one per member" -->
- inheritance (`parent.view`) gives the readers of each ancestor's own items, read from the closure table;
- `rel.perm` to another type's object copies that object's readers in, or gives the group's key where the type is
  a group's (named as a subject somewhere: `org.admin` gives `org#admin:1`);
- a condition on the row (`not {confidential}`) is evaluated on it, and `or` is a union;
- `and`, or `and not`, between parts that depend on who asks (`writer and view`, a deny) can't be one key: there
  the readers are the principals that hold a key of every part and of no denied one. <!-- checked: tests/difftest.py "the sync index: " -->
  Where nothing is denied, the keys stay as they are.

### Keyed by folder

Copied in, a file's readers are those of each folder above it: a move rewrites the readers of every file below the
moved folder, and a share on a folder those of every file below it. With `by folder`, the readers of what inherits
are keys of their own instead:

- a file's readers are its own keys and its folder's group keys (`folder#view:7`, and `folder#edit:7` where it reads
  edit), and a folder's, its own (`folder#view:7`); <!-- checked: tests/sync.sh "keyed by folder: a file's readers are its own keys and its folder's group keys, not the readers of each folder above"; tests/sync.sh "... a folder's, its own group key" -->
- each principal holds the key of every folder it may read, worked out from the readers of each folder above, as
  the groups' are. <!-- checked: tests/sync.sh "... and each user holds the key of every folder they may read" -->

So a move rewrites no file's readers: the keys of those who gain or lose the moved folders change. A share on a
folder changes the keys of whom it shares with. <!-- checked: tests/sync.sh "... and the move rewrote no file's readers: only the keys of those who gain or lose the folder"; tests/sync.sh "keyed by folder: a share on Keys: frank reads the file in it, through his keys alone" -->
The engines' filter is the same one join. What it costs: each principal's keys grow with the folders it may read
([Limits](limits.md)).

`by` names a type with a permission that inherits (`parent.view`, a recursion through several types too), which the
synced permission reaches, through dots or as its own. Who holds it must be a union of what gives it: a recursion
that joins parts that depend on who asks with `and` or `not` gives no key.
Compiling refuses a line keyed by a type it can't be keyed by (AZ810). <!-- checked: tests/policy_errors.py "a sync line keyed by a type there isn't"; tests/policy_errors.py "a sync line keyed by a type whose inheritance it doesn't reach"; tests/policy_errors.py "a sync line keyed by an inheritance worked out with and / not" -->
A permission of that type that doesn't inherit is copied in, as without `by`. <!-- checked: tests/difftest.py "the sync index: " -->

## Up to date

- In the same transaction as the change: each trigger that may change access notes what it changed, and at commit
  the readers of those objects, and of what reads them, are worked out again. <!-- checked: tests/sync.sh "a share made: frank reads file 13"; tests/sync.sh "a folder moved out of reach: the file in it leaves those who read it through Engineering"; tests/sync.sh "a team left: bob no longer reads file 13, reached through Backend; file 12, shared with him too, stays"; tests/sync.sh "a sub-team moved out: its members leave what the team above it was given"; tests/sync.sh "confidential set: the file leaves those who read it only through its folder"; tests/sync.sh "a transaction rolled back changes nothing in the index" -->
  What is written is the difference: a move rewrites the readers of what is below the moved folder (keyed by folder:
  the keys of those who gain or lose it), a membership change the member's keys.
- Two writers whose work meets queue, and the others don't wait for each other. At commit, before it reads
  anything, the work takes lock rows: of the objects it works out (what changed, and what reads it), and, shared, of
  those it reads (the folders above, what they link to); a lock row stands for every object and key whose name
  hashes to it, out of 4,096. A writer whose work writes what another's writes or reads waits for it to commit,
  then sees what it committed. <!-- checked: tests/sync.sh "a share on a Globex file doesn't wait for a share on Design docs to commit: their work meets nowhere"; tests/sync.sh "... one on a file in Design docs waits: its work writes what the other's does"; tests/sync.sh "a share on the folder another one moves into waits for the move: the move's work reads it"; tests/sync.sh "... then its work sees the move: carol reads the file in the moved folder" -->
  The keys are kept under one lock row, taken last, by the work that changes them: a membership change, a share
  to someone on a folder keyed by folder. <!-- checked: tests/interleave.py "the sync index doesn't match a rebuild" -->
  A policy whose synced permissions join parts that depend on who asks with `and` or `not` (a deny) works its
  readers out from the keys: there every commit's work queues on that one lock row. <!-- checked: tests/sync.sh "the other forms, applied" -->
- In REPEATABLE READ or SERIALIZABLE, a writer takes every lock row, and one whose snapshot is older than another's
  index write gets a serialization error (40001), to retry. <!-- checked: tests/sync.sh "REPEATABLE READ: a writer with a snapshot older than another's index write gets a serialization error" -->
- Shares that start or end later change who reads their objects with no write. `authz.sync_tick()` works out
  again the readers of the shares whose start or end passed since it last ran, and says how many shares. Schedule
  it ([Operations](../operations.md)); until it runs, the index says what it said before. <!-- checked: tests/sync.sh "a second later, before the tick: the index still says so (its stated window)"; tests/sync.sh "authz.sync_tick() works out again the readers of the shares that ended or began since it last ran, and says how many"; tests/sync.sh "after the tick: file 13 is gone, file 12 is there" -->
- Applying keeps the index's tables, so the engines keep their shapes on them, and keeps their rows when what they
  are worked out by didn't change. <!-- checked: tests/sync.sh "applying again leaves the index's rows where they are (none written again)"; tests/sync.sh "... and so does rowstile reapply" -->
  Otherwise it works them out again and writes the difference. <!-- checked: tests/sync.sh "a synced permission changed: the rows that stay are kept, the others written" -->
  A table no longer synced goes; a policy without sync lines drops the index, and so does `rowstile remove`. <!-- checked: tests/sync.sh "a table no longer synced: its readers table goes, the others stay"; tests/sync.sh "a policy without sync lines: applying it drops the index and its functions"; tests/sync.sh "rowstile remove drops the index" -->
- What is written in replica mode isn't followed, as for the closure tables ([How it works](guarantees.md)).
  `authz.sync_verify()` compares the index with a rebuild, and `rowstile reapply --force` works it out again. <!-- checked: tests/sync.sh "authz.sync_verify() finds the index stale after a write it didn't follow"; tests/sync.sh "rowstile reapply, forced, works it out again" -->

`authz.sync_tick()`, `authz.sync_verify()`, `authz.sync_work()` and `authz.sync_behind()` are for administrators:
the app role can't call them. <!-- checked: tests/sync.sh "the app role can't call authz.sync_tick(), authz.sync_verify(), authz.sync_work() or authz.sync_behind()" -->

### After commit

With `sync after commit`, a writer's transaction notes what its change reached, in `authz_sync.pending`, which
commits with it, and writes nothing of the index; a worker works the notes into the index after, in a transaction of
its own. Writers don't wait for
the index, nor for each other on it, and a big move costs its writer what it costs without the index. <!-- checked: tests/sync.sh "after commit: a revoke, a move, a team left and a row condition write nothing of the index"; tests/sync.sh "after commit: a writer doesn't wait for a worker at work" -->
The index is late instead:

- `SELECT authz.sync_work()` works in every change committed when it starts, and says how many objects it worked
  on. Call it in a loop, or schedule it (pg_cron, the app's jobs), as often as the engines' clients should hear of
  a change: the index is as late as its last run, plus how long the run takes. <!-- checked: tests/sync.sh "authz.sync_work() works the change into the index, and says how many objects it worked on"; tests/sync.sh "after commit: a share made isn't in the index before the worker runs" -->
- One works at a time: while another is at work, a call does nothing and says 0. <!-- checked: tests/sync.sh "... and while one works, another does nothing" -->
- A run that fails, is stopped, or whose server stops, leaves the changes where they were: the next run works them
  in. Nothing is lost while no worker runs, and applying works in what waits. <!-- checked: tests/sync.sh "after commit: a run rolled back (one that fails, or is stopped) leaves the changes waiting"; tests/sync.sh "... and the next run works them in"; tests/sync.sh "applying works in what waits" -->
- `authz.sync_behind()` says how long the oldest change the index doesn't hold yet has waited, and is NULL when it
  holds every one committed. <!-- checked: tests/sync.sh "... authz.sync_behind() says how long it has waited"; tests/sync.sh "... and nothing waits" -->
- `authz.sync_verify()` is false while changes wait, and says how many in a notice. <!-- checked: tests/sync.sh "... and authz.sync_verify() says the index is behind, and is false" -->
- Shares that end are noted by `authz.sync_tick()`, for the worker. <!-- checked: tests/sync.sh "after commit: authz.sync_tick() notes the shares whose end passed, for the worker" -->

The engines see the index as the worker leaves it: a revoke reaches them after the next run, and then after their
own replication lag. Until then a client keeps getting what it may no longer read. <!-- checked: integrations/electric/tests/shapes.test.ts "E17: after commit, a share arrives once the worker runs, and not before" -->
In the same transaction (the default), `authz.sync_work()` has nothing to do and says 0, and
`authz.sync_behind()` is NULL. <!-- checked: tests/sync.sh "in the same transaction, nothing waits: authz.sync_work() has nothing to do, and authz.sync_behind() is null" -->

## What it leaves out

The index fails closed: what it can't follow, compiling refuses, and what it leaves out gives nothing through it. <!-- checked: tests/policy_errors.py "a synced permission reading the clock"; tests/difftest.py "without shares that have a caveat and without links" -->

| in what a synced permission reads | the index |
|---|---|
| a condition on the clock or chance (`now()`, `'today'`, `random()`) | refused (AZ804) <!-- checked: tests/policy_errors.py "a synced permission reading the clock"; tests/policy_errors.py "a synced permission reading chance" --> |
| a condition on who asks or the session (`authz.uid()`, `authz.ctx()`, `current_user`) | refused (AZ805) <!-- checked: tests/policy_errors.py "a synced permission reading who asks"; tests/policy_errors.py "a synced permission reading the session" --> |
| a condition that reads other rows (a subquery, the app's function), in a permission, a type's or a link table's `where` | refused (AZ806); one that limits inheritance is followed by its closure table <!-- checked: tests/policy_errors.py "a synced permission reading other rows"; tests/policy_errors.py "a synced type whose where reads other rows"; tests/difftest.py "the sync index: " --> |
| a group inside itself whose members are worked out with `and` / `not` | refused (AZ807) <!-- checked: tests/policy_errors.py "a nested group whose members are worked out with and / not, synced" --> |
| a share with a caveat | gives nothing: a caveat is checked at each request. Applying warns of those there are |
| a share link | gives nothing: a synced client is a principal, without links. Applying warns of those there are |
| scopes, view-as | not in the index: the app's proxy refuses a session limited by them ([Electric](#electric)) <!-- checked: integrations/electric/tests/shapes.test.ts "E15: a session limited by scopes is refused, 403"; integrations/electric/tests/proxy.test.ts "E15: viewing as someone is a session limited too: refused" --> |
| a masked column | applying refuses a sync role that may read one (AZ809); lint reports a grant or a publication since <!-- checked: tests/sync.sh "a sync role that may read a masked column is refused"; tests/sync.sh "lint finds a masked column the sync role may read, granted since" --> |


## The sync role and lint

With sync lines, `authz.lint()` reports these as errors:

- the sync role doesn't exist; <!-- unchecked: applying refuses a sync role that isn't there (AZ808), so lint meets one only when it was dropped since -->
- it is a member of the app role, or the app role of it: the app would read every row through it; <!-- checked: tests/sync.sh "lint finds a sync role made a member of the app role since" -->
- it lacks BYPASSRLS: the rules apply to the app role, so it reads no row of a table with rules, and an engine's
  first snapshot is empty while the changes it decodes hold every row; <!-- checked: tests/sync.sh "lint finds a sync role without BYPASSRLS: its engine's first snapshot is empty" -->
- it may read a masked column, or a publication publishes one; <!-- checked: tests/sync.sh "lint finds a masked column the sync role may read, granted since"; tests/sync.sh "lint finds a publication that publishes a masked column" -->
- it owns a governed table, or is a member of its owner: an owner may turn row-level security off; <!-- checked: tests/sync.sh "lint finds a governed table the sync role owns" -->
- a privilege on `authz_sync` that the policy doesn't give. Applying takes it back. <!-- checked: tests/sync.sh "lint reports a privilege on the index the policy doesn't give"; tests/sync.sh "applying again takes back the privilege on the index the policy doesn't give" -->

The engine is trusted: it holds BYPASSRLS and every row, and rowstile can't check what it serves
([the threat model](../threat-model.md)). <!-- unchecked: what an engine serves is the engine's, outside the database -->

## Electric

[Electric](https://electric-sql.com) serves shapes over HTTP: the rows of one table that match a filter, and their
changes as they happen. Clients ask the app's own server, and it asks Electric. The server asks the database who
the request is, sets the shape's filter for that principal, and passes Electric's answer on. rowstile writes the
filters, and the TypeScript SDK has the route that sets them. This is a preview too: `integrations/electric` runs
it on Electric 1.8.1, in each of the index's modes (copied in, keyed by folder, after commit). The
[Electric stack page](../stacks/electric.md) shows the app's side from end to end.

### Electric's role and its publication

Electric connects as the sync role, in its manual publication mode (`ELECTRIC_MANUAL_TABLE_PUBLISHING=true`), so it
owns no table and can't turn row-level security off. <!-- checked: tests/sync.sh "lint finds a governed table the sync role owns" -->
The role is made by whoever runs the database: a role that may make roles can give REPLICATION and BYPASSRLS only
when it holds them. <!-- unchecked: Postgres's own rule for CREATEROLE, from version 16 -->
The grants and the publication can be the app's migration, after the policy's (the index's tables must be there):

<!-- not run: it needs the sync role, which the docs app the reference runs on has none of; integrations/electric's migrations do this -->
```sql
CREATE ROLE conf_electric LOGIN REPLICATION BYPASSRLS PASSWORD '...';   -- as an administrator
GRANT USAGE ON SCHEMA app TO conf_electric;
GRANT SELECT ON app.files, app.folders TO conf_electric;
ALTER TABLE app.files REPLICA IDENTITY FULL;            -- Electric asks for every column of the old row
ALTER TABLE app.folders REPLICA IDENTITY FULL;
CREATE PUBLICATION electric_publication_default FOR TABLE app.files, app.folders,
  authz_sync.keys, authz_sync.file__readers, authz_sync.folder__readers;
```

The publication holds the synced tables and the index's tables their filters read: `keys`, and each synced table's
readers. Electric adds nothing to it in this mode: a table added later is synced from the next shape that asks
for it.

A table with a masked column can't be in it whole: Electric asks for `REPLICA IDENTITY FULL`, and Postgres then
refuses an update or a delete of the table when a publication's column list leaves a column out. <!-- unchecked: Postgres's own rule for column lists; integrations/electric publishes the notes only to show lint finds it -->
So a publication of the table carries the masked column to Electric, and `authz.lint()` reports it. <!-- checked: integrations/electric/tests/shapes.test.ts "E13: a masked column is never in a shape" -->
Keep such a column in a table of its own, which isn't synced.

### The shapes: `rowstile client electric`

`rowstile client electric` writes each synced table's shape as TypeScript constants (with `electric =
"src/shapes.gen.ts"` under `[clients]`, `rowstile client` and `rowstile dev` write it). Only the policy's names and
the filter's text are in it: <!-- checked: tests/unit_test.py "test_electric_shapes" -->

<!-- not run: generated for the policy above, by rowstile client electric -->
```ts
export const shapes = {
  "app.files": {
    "table": "app.files",
    "keys": ["id"],                  // the key columns: always synced
    "masked": [],                    // the columns the policy masks: never synced
    "where": {
      "user": "\"id\" IN (SELECT \"id\" FROM authz_sync.\"file__readers\" WHERE \"key\" IN (SELECT \"key\" FROM authz_sync.\"keys\" WHERE \"principal_type\" = 'user' AND \"principal_id\" = $1))"
    }
  }
} as const;
```

`where` holds the index's one join for each type that signs in, `$1` the principal's id. Electric follows the
nested `IN (SELECT ...)`: a key gained or lost, a reader added or taken away, moves rows in or out of each shape
that reads it, with no write to the rows. <!-- checked: integrations/electric/tests/shapes.test.ts "E2: a share made: the row arrives live; revoked: it leaves"; integrations/electric/tests/shapes.test.ts "E4: a team left" -->

### The route: `electricShape`

`electricShape(shape, options)` (`@rowstile/client`) is a route handler, fetch's `Request` to its `Response`, for
GET and POST (a subset):

<!-- not run: TypeScript; integrations/electric/src/app.ts is this route, and its checks run it -->
```ts
import { actingAs, electricShape, syncPrincipal } from "@rowstile/client";
import { shapes } from "./shapes.gen.js";

export const files = electricShape(shapes["app.files"], {
  url: process.env.ELECTRIC_URL!,          // Electric's /v1/shape: only the server reaches it
  secret: process.env.ELECTRIC_SECRET,
  signedIn: (req) => actingAs(userOf(req), () => sql.transaction((c) => syncPrincipal(c))),
  vary: ["cookie"],                        // the request headers that tell users apart
});
```

`signedIn` asks the database who the request is, in the app's own way: `syncPrincipal(c)` in a transaction signed
in as the request's user, or after `authz.login_key()` or `authz.login_jwt()`. Every request asks, live polls too.
Then the route:

- answers 401 (AZ714) for nobody, or for a user who isn't there, and asks nothing of Electric; <!-- checked: integrations/electric/tests/shapes.test.ts "E9: not signed in: 401, and no shape is made"; integrations/electric/tests/proxy.test.ts "E9: not signed in, nothing is asked of Electric" -->
- answers 403 (AZ704) for a session limited by scopes (a key's, a token's) or viewing as someone, as
  `authz.session_limited()` says ([Identity](identity.md)): the index holds what each principal may read, without
  scopes; <!-- checked: integrations/electric/tests/shapes.test.ts "E15: a session limited by scopes is refused, 403"; integrations/electric/tests/proxy.test.ts "E15: viewing as someone is a session limited too: refused" -->
- sets the shape's `table`, `where`, `params[1]` (the principal's id) and Electric's `secret` itself, whatever the
  client sent; <!-- checked: integrations/electric/tests/shapes.test.ts "E8: users at once, in rounds, each get their own" -->
- refuses a client's own `where`, `params`, another `table`, `queryable_columns` or `secret`, 400 (AZ710). <!-- checked: integrations/electric/tests/shapes.test.ts "E8: users at once, in rounds, each get their own" -->
  Anded
  in, a filter that reads other tables would tell the client which rows match there, rows it may not read; left
  out, the client would get more than it asked for. <!-- checked: integrations/electric/tests/shapes.test.ts "E8: users at once, in rounds, each get their own" -->
  A client narrows with Electric's subsets instead (`subset__where`, or a POST's body), which Electric adds to the
  filter with AND, keeps free of subqueries and limits to the synced columns; <!-- checked: integrations/electric/tests/shapes.test.ts "E8: users at once, in rounds, each get their own" -->
- refuses a POST whose body is more than a subset (`where`, `params`, `limit`, `offset`, `order_by`), 400; <!-- checked: integrations/electric/tests/shapes.test.ts "E8: users at once, in rounds, each get their own" -->
- always syncs the key columns, and never a masked one. <!-- checked: integrations/electric/tests/shapes.test.ts "E13: a masked column is never in a shape, even when the client asks for it" -->
  A client may narrow `columns`; one that names a masked column, or a column the route doesn't sync, is refused
  with a 400. <!-- checked: integrations/electric/tests/shapes.test.ts "E13: a masked column is never in a shape, even when the client asks for it" -->
  A table the policy masks a column of needs `columns` in the options, which leave it out, and they are the
  shape's `queryable_columns` too, so a subset can't filter on another; <!-- checked: integrations/electric/tests/shapes.test.ts "E13: a masked column is never in a shape, even when the client asks for it"; integrations/electric/tests/proxy.test.ts "what the route refuses to be set up with" -->
- answers with `Vary` on the headers `vary` names (and Electric's own), so a cache in front of it keeps a copy for
  each user and never gives one user's shape to another. <!-- checked: integrations/electric/tests/shapes.test.ts "E10: answers vary on who asks, and a cache never gives one user's shape to another" -->

Applying the policy, applying it again and a changed policy leave the shapes as they are: the same handles, no
409 and no `must-refetch`. <!-- checked: integrations/electric/tests/shapes.test.ts "E12: lint, then rowstile apply and reapply leave the shapes as they are" -->
A user deleted loses their keys, so their shape empties; the route then answers them 401. <!-- checked: integrations/electric/tests/shapes.test.ts "E14: a user deleted: their keys go, and their shape empties" -->

### Its limits

- Rows already on a device stay there while it is offline, and in any copy the client keeps. <!-- unchecked: what a client keeps is the client's, outside the database -->
  A revoke stops delivery: Electric then sends a move-out, an event naming the values that no longer match, and no
  delete, which the client must apply. <!-- checked: integrations/electric/tests/shapes.test.ts "E2: a share made: the row arrives live; revoked: it leaves" -->
  Electric's own `Shape` (`@electric-sql/client` 1.5.28) doesn't apply them: it keeps the row until the shape is
  fetched again. <!-- checked: integrations/electric/tests/shapes.test.ts "Electric's own Shape keeps a row that moved out" -->
  Read the stream's move-out events (the conformance suite's tests follow them as Electric's Elixir client does),
  or use a client that applies them.
- The window after a change is Electric's replication lag, and for a share that ends, until the next
  `authz.sync_tick()` too. <!-- checked: integrations/electric/tests/shapes.test.ts "E6: a share that ends: the row leaves at the next authz.sync_tick(), and not before" -->
- What the index leaves out (caveats, links, scopes) gives nothing through Electric either. <!-- checked: tests/difftest.py "without shares that have a caveat and without links" -->
- Electric is trusted: it holds BYPASSRLS and every row of what it publishes, and rowstile can't check what it
  serves. <!-- unchecked: what an engine serves is the engine's, outside the database -->
  The conformance suite checks it end to end, for the forms it uses.

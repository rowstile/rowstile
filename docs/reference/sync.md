# The sync index (a preview)

Sync engines (Electric, Zero, PowerSync) read Postgres by logical replication, then decide on their own servers
which rows each client gets. Row-level security doesn't run on that path, so an engine has to be told the rules
again. The sync index tells it: for each row of a synced table, the keys that may read it, kept in tables the engine
replicates like any other, in the same transaction as the change. <!-- checked: tests/sync.sh "a share made: frank reads file 13"; tests/sync.sh "a transaction rolled back changes nothing in the index" -->

This is a preview. Its lines, tables and functions may change in any release, and it is outside what 1.0 will
promise. This release makes the index in the database; the engines' own filters and a proxy come later.

## Declaring it

<!-- not run: applying needs the sync engine's role; tests/sync.sh applies this policy, the docs app's with these lines -->
```authz
sync role sync_engine        -- the engine's Postgres role
sync app.files : view        -- each file's readers hold view on it
sync app.folders             -- no permission: the table's select rule
```

- `sync role` names the role the engine connects as. Make it for the engine: `CREATE ROLE sync_engine LOGIN
  REPLICATION BYPASSRLS`. It can't be the app role or PUBLIC (AZ803). <!-- checked: tests/policy_errors.py "the app role as the sync role"; tests/policy_errors.py "PUBLIC as the sync role" -->
  Applying refuses a role that isn't there, one that is a member of the app role or has it as a member, and one
  that is a member of the role applying the policy (AZ808). <!-- checked: tests/sync.sh "a sync role that isn't there is refused"; tests/sync.sh "a sync role that is a member of the app role is refused"; tests/sync.sh "... and so is one the app role is a member of"; tests/sync.sh "... and so is one that is a member of the policy's owner" -->
- `sync schema.table : permission` names a type's table, one line each, and the permission its readers hold. With
  no permission, they hold the table's select rule, which the table must have (AZ801). <!-- checked: tests/policy_errors.py "a sync line naming no permission, for a table without a select rule"; tests/policy_errors.py "a sync line naming a permission its type hasn't" -->
- Sync lines need a sync role, and a sync role needs a sync line (AZ802). <!-- checked: tests/policy_errors.py "sync lines and no sync role"; tests/policy_errors.py "a sync role and nothing synced" -->

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

A key is one of these:

- a principal: `user:42`, `service:7`;
- every signed-in principal of a type: `user:*`;
- `anyone`;
- a group: the holders of a relation or permission of a group's object, `team#member:10` or `org#admin:1`.

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

## Up to date

- In the same transaction as the change: each trigger that may change access notes what it changed, and at commit
  the readers of those objects, and of what reads them, are worked out again. <!-- checked: tests/sync.sh "a share made: frank reads file 13"; tests/sync.sh "a folder moved out of reach: the file in it leaves those who read it through Engineering"; tests/sync.sh "a team left: bob no longer reads file 13, reached through Backend; file 12, shared with him too, stays"; tests/sync.sh "a sub-team moved out: its members leave what the team above it was given"; tests/sync.sh "confidential set: the file leaves those who read it only through its folder"; tests/sync.sh "a transaction rolled back changes nothing in the index" -->
  What is written is the difference: a move rewrites the readers of what is below the moved folder, a membership
  change the member's keys.
- Two writers at once queue on a lock row of each synced type their change reaches. In REPEATABLE READ or
  SERIALIZABLE, a writer whose snapshot is older than another's index write gets a serialization error (40001),
  to retry. <!-- checked: tests/sync.sh "REPEATABLE READ: a writer with a snapshot older than another's index write gets a serialization error" -->
- Shares that start or end later change who reads their objects with no write. `authz.sync_tick()` works out
  again the readers of the shares whose start or end passed since it last ran, and says how many shares. Schedule
  it ([Operations](../operations.md)); until it runs, the index says what it said before. <!-- checked: tests/sync.sh "a second later, before the tick: the index still says so (its stated window)"; tests/sync.sh "authz.sync_tick() works out again the readers of the shares that ended or began since it last ran, and says how many"; tests/sync.sh "after the tick: file 13 is gone, file 12 is there" -->
- Applying keeps the index's tables, so the engines keep their shapes on them, and keeps their rows when what they
  are worked out by didn't change. <!-- checked: tests/sync.sh "applying again leaves the index's rows where they are (none written again)"; tests/sync.sh "... and so does rowstile reapply" -->
  Otherwise it works them out again and writes the difference. <!-- checked: tests/sync.sh "a synced permission changed: the rows that stay are kept, the others written" -->
  A table no longer synced goes; a policy without sync lines drops the index, and so does `rowstile remove`. <!-- checked: tests/sync.sh "a table no longer synced: its readers table goes, the others stay"; tests/sync.sh "a policy without sync lines: applying it drops the index and its functions"; tests/sync.sh "rowstile remove drops the index" -->
- What is written in replica mode isn't followed, as for the closure tables ([How it works](guarantees.md)).
  `authz.sync_verify()` compares the index with a rebuild, and `rowstile reapply --force` works it out again. <!-- checked: tests/sync.sh "authz.sync_verify() finds the index stale after a write it didn't follow"; tests/sync.sh "rowstile reapply, forced, works it out again" -->

`authz.sync_tick()` and `authz.sync_verify()` are for administrators: the app role can't call them. <!-- checked: tests/sync.sh "the app role can't call authz.sync_tick() or authz.sync_verify()" -->

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
| scopes, view-as | not in the index: an app's proxy refuses a scoped session <!-- unchecked: the proxy is the app's, and comes with the engines' stage --> |
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

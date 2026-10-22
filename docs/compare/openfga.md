# rowstile and OpenFGA

Both answer "who may do what to which object", and both describe it with relations: an editor, a member, a
parent. They differ in where the facts live. OpenFGA is a service with a store of its own, which the app
writes to and asks. rowstile is a compiler: the facts stay in the app's Postgres tables, and Postgres applies
the rules to every query.

What this page says of OpenFGA is from its own documentation, read on 2026-10-07 and linked. If a line is wrong
or out of date, an issue is welcome. The short version for every alternative is on
[rowstile and the alternatives](../comparison.md).

## The same model in both

Documents in folders, edited by people and by a team's members, where a folder's editors may edit what is
inside it. In OpenFGA's language, put together from two pages of its modeling guide
([parent and child objects](https://openfga.dev/docs/modeling/parent-child),
[user groups](https://openfga.dev/docs/modeling/user-groups)):

```
model
  schema 1.1

type user

type team
  relations
    define member: [user]

type folder
  relations
    define editor: [user, team#member]

type document
  relations
    define parent: [folder]
    define editor: [user, team#member] or editor from parent
```

In rowstile's:

```authz
app role app_user

type user = app.users

type team = app.teams
  member : user = app.team_members(team_id -> user_id)

type folder = app.folders
  editor : user        = app.folder_editors(folder_id -> user_id)
  editor : team#member = app.folder_teams(folder_id -> team_id)

  can edit = editor

type document = app.documents
  parent : folder      = folder_id
  editor : user        = app.document_editors(document_id -> user_id)
  editor : team#member = app.document_teams(document_id -> team_id)

  can edit = editor or parent.edit

rules app.documents
  select                 : edit
  update                 : edit
  update folder_id after : parent.edit
```

The two read alike, and that is no accident: both follow the same idea of relations and of permissions built
from them. The differences are in the parts that have no twin. `= app.documents`, `= folder_id` and
`= app.team_members(team_id -> user_id)` say where each fact already is in the app's tables: a column, or a
link table. `rules app.documents` says what a `SELECT` and an `UPDATE` on the table need. Its last line has
no twin either: the folder a document is in gives `edit` on it, so the policy also says where a document
may be moved (into a folder its mover may edit).

## When a fact changes

In OpenFGA a fact is a relationship tuple in its store, and the app writes it. For a document put in a
folder, its guide writes:

```
user: folder:notes
relation: parent
object: document:meeting_notes.doc
```

The document's row is in the app's database and this tuple is in OpenFGA's: two writes to two systems. The
app decides what happens when the second one fails, and something has to bring the two back in step after a
restore of either.

With rowstile there is nothing more to write. The document's `folder_id` is the fact, a team's members are
the rows of `app.team_members`, and a folder's editors the rows of `app.folder_editors`: the `INSERT` the
app makes anyway, in the same transaction as whatever else the request does. Both commit, or neither.

For access that people hand each other while the app runs, a relation can also come from shares. With
one more line under `document`, `editor : user shared by edit`, the call
`authz.share('document', '7', 'editor', 'user', '4')` writes one, in the same transaction, and
`shared by edit` says who may share: whoever may edit the document.

## Asking

The app calls OpenFGA's Check before it acts: "Check can be called if you need to establish whether a
particular user has a specific relationship with a particular object"
([relationship queries](https://openfga.dev/docs/interacting/relationship-queries)). Every handler that
forgets to ask is open.

With rowstile the app doesn't ask. Each transaction says who is signed in, and Postgres filters what a query
reads and refuses what it may not write, for any query that arrives: the ORM's, a report's, one a developer
forgot to guard. `authz.can()` is there for what the page shows (a button, a menu).

## Lists

"The documents I may edit, by name, page 3" is where the two differ most. OpenFGA's guide to
[searching with permissions](https://openfga.dev/docs/interacting/search-with-permissions) gives three ways:
search in your database and then check each result; keep a local index of who may see what, fed from
OpenFGA's changes; or ask ListObjects for the ids and then query. ListObjects returns what it found within a
time limit (3 seconds by default) up to a maximum (1,000 by default), and of the third way the guide says:
"A partial list from the API is not enough, because you won't be able to sort using it."

With rowstile it is a query:

```sql
SELECT id, title FROM app.documents ORDER BY title LIMIT 50 OFFSET 100;
```

Postgres joins the rules into the plan, uses the tables' indexes, sorts and pages.

## Consistency

OpenFGA can cache. Its cache is off by default, and then every answer is consistent with its store. With
the cache on, the default mode serves answers from it, and its docs say: "If you write a tuple and you
immediately make a Check on a relation affected by that tuple using `MINIMIZE_LATENCY`, the tuple change
might not be taken in consideration if OpenFGA serves the result from the cache." A query can ask for
`HIGHER_CONSISTENCY` instead, which skips the cache
([consistency](https://openfga.dev/docs/interacting/consistency)).

rowstile has no cache to be behind: a rule reads the rows as the transaction sees them. Inheritance is kept
in tables by triggers, in the same transaction as the write that changes it.

## What runs

OpenFGA is a server and its datastore, to deploy, scale and watch: its guide to
[configuring a server](https://openfga.dev/docs/getting-started/setup-openfga/configure-openfga) lists Postgres,
MySQL and SQLite as storage engines, beside one in memory. rowstile leaves SQL in the database
(row-level security policies, views, tables for inheritance, functions) and runs nothing beside it. The
`rowstile` command is needed to change the policy, not to serve requests.

## When OpenFGA is the better choice

- **What decides access is spread out**: several databases, several services, or not in Postgres at all. A
  service is then the one place that can know everything. rowstile reads one Postgres database.
- **Many services in several languages** ask the same questions. OpenFGA has SDKs and an API for that;
  rowstile's rules reach only what connects to the database.
- **One type takes many structural writes a second.** In rowstile, moves and links in a tree wait for each
  other ([Speed and limits](../reference/limits.md)).
- **You need an organisation behind it.** OpenFGA is "a Cloud Native Computing Foundation incubating
  project" ([openfga.dev](https://openfga.dev/)). rowstile is in beta, with one maintainer, and nobody
  outside has audited it ([how it is checked](../how-it-is-checked.md)).

## Try the same model

Two tested recipes hold the two halves of this page's model, each with a link that opens it in the playground:
[folders that inherit](../cookbook/folders-that-inherit.md) and
[teams inside teams](../cookbook/teams-inside-teams.md).

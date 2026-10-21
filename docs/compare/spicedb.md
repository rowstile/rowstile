# rowstile and SpiceDB

Both describe access with relations and with permissions built from them. SpiceDB calls itself "an
open-source, Google Zanzibar-inspired database system for real-time, security-critical application
permissions" ([its introduction](https://authzed.com/docs/spicedb/getting-started/discovering-spicedb)): it
runs as a service beside the app's own database, and the app writes relationships to it and asks it.
rowstile is a compiler: the relationships are the rows the app already has, and Postgres applies the rules
to every query.

What this page says of SpiceDB is from its own documentation, read on 2026-10-07 and linked. If a line is wrong
or out of date, an issue is welcome. The short version for every alternative is on
[rowstile and the alternatives](../comparison.md).

## The same model in both

Documents in folders, edited by people and by a team's members, where a folder's editors may edit what is
inside it. In SpiceDB's schema language, written with the forms its
[schema page](https://authzed.com/docs/spicedb/concepts/schema) shows (a subject relation, `team#member`; a
union, `+`; an arrow, `parent->edit`):

```
definition user {}

definition team {
    relation member: user
}

definition folder {
    relation editor: user | team#member
    permission edit = editor
}

definition document {
    relation parent: folder
    relation editor: user | team#member
    permission edit = editor + parent->edit
}
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

`parent->edit` and `parent.edit` are the same step: SpiceDB's page says the arrow walks "from the
`parent_folder` of the `document`" to "the subjects found for the `read` permission of that folder". What
rowstile adds is where each relation is read from, a column (`= folder_id`) or a link table
(`= app.team_members(team_id -> user_id)`), and what each command on the table needs (`rules`). The last rule
is about moving a document: the folder it is in gives `edit` on it, so the policy also says where it may be
moved (into a folder its mover may edit).

## When a fact changes

In SpiceDB a fact is a relationship the app writes to it. The document's row is in the app's database and
its `parent` relationship is in SpiceDB: two writes to two systems, and the app decides what happens when the
second one fails.

With rowstile there is nothing more to write: `folder_id` is the relationship, and a folder's editors are
the rows of `app.folder_editors`, the `INSERT` the app makes anyway. For access people hand each other
while the app runs, a relation can be `shared` instead: `authz.share('document', '7', 'editor', 'user',
'4')` writes it, in the same transaction as the rest of the request, and the policy says who may share.

## Consistency

SpiceDB lets each request choose. Its default for reads is `minimize_latency`, which "will attempt to
minimize the latency of the API call by selecting data that is most likely to exist in the cache". For an
answer that is at least as new as a given write, the app passes a ZedToken, "an opaque token representing a
point-in-time of the SpiceDB datastore". Its docs describe keeping that token in the app's own database,
beside the content it protects ("For a Postgres table this can be a standard `text` column"), and updating
it when the content or the access to it changes. `fully_consistent` asks for the latest data instead
([consistency](https://authzed.com/docs/spicedb/concepts/consistency)).

rowstile has no second clock. A rule reads the rows as the transaction sees them, and there is no token to
keep.

## Conditions

SpiceDB's caveats are "expressions that can return true or false, and they can be attached (by name) to
relationships", written in CEL. Part of their values is stored with the relationship and the rest comes
with each check; the page's own example lets a viewer in only from an IP range
([caveats](https://authzed.com/docs/spicedb/concepts/caveats)).

rowstile has two kinds. A condition in the policy is SQL on the row: `can view = edit or {published}`,
`update : edit and {not archived}`. It reads what the row holds, and needs nothing sent with the question.
A caveat goes with one share and is checked at each request, as SpiceDB's is:
`caveat from_ip = {authz.ctx('ip') = arg('ip')}`, where `arg('ip')` is what the share was made with and
`authz.ctx('ip')` what the app said of this request in its transaction
([the policy language](../reference/language.md)).

## Lists

SpiceDB's guide to
[protecting a list endpoint](https://authzed.com/docs/spicedb/modeling/protecting-a-list-endpoint) states the
question plainly: "In a system protected by SpiceDB, the authorization and data concerns are separated. This
means that enforcing authorization on a list endpoint requires making a call to both the database and
SpiceDB and combining the queries into a response." It gives three ways. Ask LookupResources for every id
and filter the query with them, when "the number of resources that a user has access to is small (e.g.
less than 10,000 resources)". Or "fetch a page of resources from your database, and then call
`CheckBulkPermissions` on those resources", again until a page is full. Or keep a local copy of who may see
what, fed by Authzed Materialize, which "provides the greatest scalability of the three options"; the
guide notes that the feature it uses is "currently in early access for AuthZed Dedicated users".

With rowstile a list is a query, sorted and paged by Postgres with the rules in its plan:

```sql
SELECT id, title FROM app.documents ORDER BY title LIMIT 50 OFFSET 100;
```

## What runs

SpiceDB is a service with a datastore under it, to deploy, scale and watch. rowstile leaves SQL in the
database and runs nothing beside it.

## When SpiceDB is the better choice

- **What decides access is spread out**: several databases or services, or not in Postgres. rowstile reads
  one Postgres database.
- **Many services** ask the same questions, in several languages.
- **One type takes many structural writes a second.** In rowstile, moves and links in a tree wait for each
  other ([Speed and limits](../reference/limits.md)).
- **You need a company behind it.** "AuthZed offers both self-hosted and managed SpiceDB services and
  support" ([its products](https://authzed.com/docs/authzed/guides/picking-a-product)). rowstile is in
  beta, with one maintainer, and nobody outside has audited it
  ([how it is checked](../how-it-is-checked.md)).

## Try the same model

Two tested recipes hold the two halves of this page's model, each with a link that opens it in the playground:
[folders that inherit](../cookbook/folders-that-inherit.md) and
[teams inside teams](../cookbook/teams-inside-teams.md).

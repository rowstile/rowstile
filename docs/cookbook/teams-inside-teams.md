# Nested groups: teams inside teams

A relation can come from a link table, and it can be declared twice, with two sources. Here a team's members
are the people in it and the members of its sub-teams, to any depth, loops included.

```authz
type team = app.teams
  member : user        = app.team_members(team_id -> user_id)
  member : team#member = app.teams(parent_id -> id)

type document = app.documents
  owner  : user        = owner_id
  reader : team#member = app.document_teams(document_id -> team_id)
  can view = owner or reader
```

- `team#member` is "the members of a team". The second `member` line says: the members of a team whose
  `parent_id` is this team are members of this team too.
- `reader : team#member` gives a document to a team's members, whoever they are that day. Nobody is copied
  into a list per document: joining Web is enough to read what Engineering reads.
- Who is in a team, and which team is inside which, decide what people read: the app role reads `app.team_members`
  and `app.teams` and writes neither (`schema.sql` grants it SELECT on them). If it could insert there, anyone
  could join any team. `authz.lint()` says so of a table like that; where the app changes them, give them a type
  and rules of their own.

## Tested

Bo is in Web, Web is inside Engineering, and the document is given to Engineering:

```authz
test "what a team may read, its sub-teams' members may read"
  user $bo cannot view document $d
  given {INSERT INTO app.document_teams VALUES ($d, $eng)}
  user $bo can view document $d
  user $cy cannot view document $d
```

Dee is in Design, inside Web, inside Engineering: three levels. Bo is in Engineering, above Design, so what
Design reads he doesn't, until Engineering is put inside Design. The loop changes nothing for Dee:

```authz
test "to any depth, loops included"
  user $dee can view document $plans
  user $bo cannot view document $sketch
  given {UPDATE app.teams SET parent_id = $ui WHERE id = $eng}
  user $bo can view document $sketch
  user $dee can view document $plans
```

## Try it

[Open it in the playground](https://rowstile.dev/playground/#e=teams-inside-teams): the tables, the policy and the
tests, in your browser, with nothing to install. Or try it on a database of your own:
[the steps](../cookbook.md#trying-a-recipe-on-your-own-database) take the files of
[`docs/cookbook/teams-inside-teams/`](teams-inside-teams/). CI takes them on every change
([`core/tests/cookbook.sh`](../../core/tests/cookbook.sh)), and checks that every line of policy and tests shown here is in those files.

## What it costs

Nested groups are worked out for each query, walking up from the asker's own teams; nothing is stored for
them. [Speed and limits](../reference/limits.md) has the measure: with 20,000 teams in chains ten deep,
opening something given to the top of a chain takes 1.7 ms.

More: [subjects and groups](../reference/language.md), [sharing with a team](sharing-and-links.md),
[the other recipes](../cookbook.md).

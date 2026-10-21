# Rows only their owner can see and change

The simplest rule in Postgres row-level security: a row belongs to whoever its column names, and nobody else
sees it or changes it.

```authz
type note = app.notes
  owner : user = owner_id
  can edit = owner
  can view = owner

rules app.notes
  select          : view
  insert          : owner
  update          : edit
  update owner_id : nobody
  delete          : edit
```

- `owner : user = owner_id` reads who owns a note from the column the table already has. Nothing is copied.
- `select : view` filters every read: a query for all notes returns the asker's own.
- `insert : owner` asks that a new row names whoever is signed in as its owner, so nobody makes notes in
  someone else's name.
- `update owner_id : nobody` says outright that a note is never given away. Here `update : edit` refuses it
  too: that rule must also hold on the row after the change, and the note's owner is then someone else. The
  line matters as soon as `edit` holds for more than the owner, since an editor could make himself the owner.
  Without it, `authz.lint()` warns that whoever may update a note may change its owner.

## Tested

The test brings its own rows and rolls them back:

```authz
test "a note is its owner's"
  given ann = {INSERT INTO app.users VALUES (901, 'Ann') RETURNING id}
  given bo = {INSERT INTO app.users VALUES (902, 'Bo') RETURNING id}
  given n = {INSERT INTO app.notes (owner_id, body) VALUES ($ann, 'mine') RETURNING id}
  user $ann can edit note $n
  user $bo cannot view note $n
  as user $bo sees 0 {SELECT FROM app.notes WHERE id = $n}
  as user $bo refused {INSERT INTO app.notes (owner_id, body) VALUES ($ann, 'as Ann')}
  as user $ann refused {UPDATE app.notes SET owner_id = $bo WHERE id = $n}
```

## Try it

[Open it in the playground](https://rowstile.dev/playground/#e=owner-only): the tables, the policy and the
test, in your browser, with nothing to install. Or take the three files of
[`docs/cookbook/owner-only/`](owner-only/) (`schema.sql`, `policy.authz`, `tests.authz`) and run
`rowstile dev`. CI applies and tests them on every change (`core/tests/cookbook.sh`), and every line shown
here is in those files.

## What it costs

Nothing beyond the query: the rule is a comparison on the row's own column, so an index on `owner_id` serves
it like any other filter.

More: [relations and permissions](../reference/language.md), [the other recipes](../cookbook.md).

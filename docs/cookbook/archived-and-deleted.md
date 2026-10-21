# Soft-deleted and archived rows: read-only archives, and a trash the owner restores from

An archived document can be read and not changed. A deleted one isn't removed: it sits in its owner's trash,
and is gone for everyone it was shared with.

```authz
type document = app.documents
  owner  : user = owner_id
  viewer : user shared by share

  can share = owner
  can view  = owner or (viewer and {deleted_at is null})
  can edit  = owner and {not archived} and {deleted_at is null}

rules app.documents
  select          : view
  insert          : owner
  update          : owner
  update title    : edit
  update owner_id : nobody
```

- `{not archived}` and `{deleted_at is null}` are conditions on the row. `edit` needs both, so the title of an
  archived or deleted document can't change: `update title : edit` is checked on the row before the change.
- `update : owner` lets the owner change the other columns: archive and un-archive, delete and restore.
- `viewer and {deleted_at is null}`: the people a document was shared with lose it the moment it is deleted,
  and get it back when it is restored. The shares themselves are kept.
- The app role has no `DELETE` on the table at all: a row is marked, never removed.

## Why the owner still sees the trash

Postgres refuses an update whose result the person making it can't see ("new row violates row-level security
policy"). So if deleted rows were hidden from their owner too, the owner couldn't mark one deleted through the
app. Two ways to have rows vanish for everyone:

- keep the policy above, and let the app leave `deleted_at is not null` out of its lists;
- or write `type document = app.documents where {deleted_at is null}`: such a row holds nothing and passes
  nothing on, for everyone. Marking and restoring are then a job's, run as the tables' owner, not the app
  role's.

## Tested

```authz
test "archived: read, not changed"
  user $ann can view document $old
  user $ann cannot edit document $old
  as user $ann refused {UPDATE app.documents SET title = 'Rewritten' WHERE id = $old}
  as user $ann allowed {UPDATE app.documents SET archived = false WHERE id = $old}
  as user $ann allowed {UPDATE app.documents SET title = 'This year' WHERE id = $old}
```

```authz
test "deleted: in its owner's trash, gone for everyone else"
  user $bo can view document $d
  as user $ann allowed {UPDATE app.documents SET deleted_at = now() WHERE id = $d}
  user $bo cannot view document $d
  as user $ann sees 1 {SELECT FROM app.documents WHERE id = $d AND deleted_at IS NOT NULL}
  as user $ann refused {UPDATE app.documents SET title = 'Edited in the trash' WHERE id = $d}
  as user $ann allowed {UPDATE app.documents SET deleted_at = NULL WHERE id = $d}
  user $bo can view document $d
```

## Try it

[Open it in the playground](https://rowstile.dev/playground/#e=archived-and-deleted): the tables, the policy and
the tests, in your browser, with nothing to install. Or try it on a database of your own:
[the steps](../cookbook.md#trying-a-recipe-on-your-own-database) take the files of
[`docs/cookbook/archived-and-deleted/`](archived-and-deleted/). CI takes them on every change
(`core/tests/cookbook.sh`), and checks that every line of policy and tests shown here is in those files.

More: [rows that count, and conditions](../reference/language.md), [conditions on the row](conditions-on-the-row.md),
[the other recipes](../cookbook.md).

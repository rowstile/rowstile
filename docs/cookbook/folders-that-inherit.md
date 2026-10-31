# Folder permissions that inherit down a tree, and stop where a folder says so

`parent.edit` follows a relation back to the same type: what you may do in a folder, you may do in everything
inside it, as deep as it goes. `and {inherit}` says where that stops.

```authz
type folder = app.folders
  parent : folder = parent_id
  owner  : user   = owner_id

  can edit = owner or (parent.edit and {inherit})
  can view = edit

rules app.folders
  select                   : view
  insert                   : owner and (parent.edit or {parent_id is null})
  update                   : edit
  update parent_id after   : parent.edit
  update owner_id, inherit : owner
  delete                   : edit
```

- `parent.edit` is "whoever may edit the folder above". With `owner or`, a folder is its owner's and everyone's
  who may edit an ancestor.
- `{inherit}` is a condition on the row, in SQL: a folder with `inherit = false` takes nothing from above. Its
  own owner still holds it.
- `update parent_id after : parent.edit` is the rule for a move. A rule on a column is checked against the row
  before the change; `after` checks the row as it will be, so a folder moves only to where you may edit.
- `insert : owner and (parent.edit or {parent_id is null})` makes a folder in your own name: inside one you
  may edit, or at the top, where anyone starts a tree of their own. Without the second half nobody could
  make the first folder through the app.

## Tested

Ann owns the top folder. `$own` is inside it, says `inherit = false`, and is Bo's:

```authz
test "what you may do in a folder, you may do below it, until one says stop"
  user $ann can edit folder $low
  user $ann cannot view folder $own
  user $bo can edit folder $own
  user $bo cannot view folder $sub
  as user $ann refused {INSERT INTO app.folders (parent_id, owner_id, name) VALUES ($own, $ann, 'Notes')}
  as user $bo allowed {INSERT INTO app.folders (owner_id, name) VALUES ($bo, 'A tree of my own')}
  as user $bo refused {INSERT INTO app.folders (owner_id, name) VALUES ($ann, 'In her name')}
  as user $ann refused {UPDATE app.folders SET parent_id = $other WHERE id = $low}
  as user $ann allowed {UPDATE app.folders SET parent_id = $top WHERE id = $low}
```

## Try it

[Open it in the playground](https://rowstile.dev/playground/#e=folders-that-inherit): the tables, the policy and
the test, in your browser, with nothing to install. Or try it on a database of your own:
[the steps](../cookbook.md#trying-a-recipe-on-your-own-database) take the files of
[`docs/cookbook/folders-that-inherit/`](folders-that-inherit/). CI takes them on every change
([`core/tests/cookbook.sh`](../../core/tests/cookbook.sh)), and checks that every line of policy and tests shown here is in those files.

## What it costs

Reads stay fast however deep the tree: rowstile keeps who is above whom in a table of its own, maintained by
triggers. Writes pay for it. A move rewrites a row for each folder below the one moved, and tree writes
(moves, new and deleted folders) to one type wait for each other. [Speed and limits](../reference/limits.md) has the numbers, at a million
folders.

More: [inheritance](../reference/language.md), [hiding a subtree](deny-that-inherits.md),
[the other recipes](../cookbook.md).

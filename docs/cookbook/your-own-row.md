# Let each user edit only their own row

A relation read from the row's own key says "this row is you". People see each other's profiles and change
only their own.

```authz
type user = app.users
  self : user = id
  can edit = self

rules app.users
  select    : signed_in
  update    : edit
  update id : nobody
```

- `self : user = id` reads the relation from the key itself: the user a row is linked to is the row.
- `select : signed_in` lets anyone signed in read every profile. For "only your own", write `select : edit`.
- `update id : nobody` keeps the key from changing, whoever asks.

Which columns the app role may write at all is still Postgres's to say: here it is granted `UPDATE (name, bio)`
and nothing else on the table.

## Tested

```authz
test "people edit their own row, and only it"
  user $ann can edit user $ann
  user $ann cannot edit user $bo
  as user $ann allowed {UPDATE app.users SET name = 'Annie' WHERE id = $ann}
  as user $ann refused {UPDATE app.users SET name = 'Bob' WHERE id = $bo}
```

## Try it

[Open it in the playground](https://rowstile.dev/playground/#e=your-own-row): the tables, the policy and the test,
in your browser, with nothing to install. Or try it on a database of your own:
[the steps](../cookbook.md#trying-a-recipe-on-your-own-database) take the files of
[`docs/cookbook/your-own-row/`](your-own-row/). CI takes them on every change ([`core/tests/cookbook.sh`](../../core/tests/cookbook.sh)), and
checks that every line of policy and tests shown here is in those files.

More: [relations](../reference/language.md), [the other recipes](../cookbook.md).

# Blocking a user: nobody writes to someone who blocked them

A relation on the user type (the people this person blocked) can be followed from any row that names a
person. `recipient.has_blocked` holds when the recipient blocked whoever is signed in.

```authz
type user = app.users
  has_blocked : user = app.blocks(blocker_id -> blocked_id)

type direct_message = app.direct_messages
  sender    : user = from_id
  recipient : user = to_id

rules app.direct_messages
  select : sender or recipient
  insert : sender and not recipient.has_blocked
```

- `not recipient.has_blocked` refuses a message to someone who blocked its sender.
- The relation is read with the policy's rights, not the sender's. The app role isn't granted `app.blocks` at
  all here, so nobody can list who blocked them, and the rule still works.
- A `{condition}` with a subquery would do the same. The relation says it in the policy's words, and
  `rowstile prove` and the review can read it.

## Tested

```authz
test "nobody writes to someone who blocked them"
  as user $ann allowed {INSERT INTO app.direct_messages (from_id, to_id, body) VALUES ($ann, $bo, 'hi')}
  given {INSERT INTO app.blocks VALUES ($bo, $ann)}
  as user $ann refused {INSERT INTO app.direct_messages (from_id, to_id, body) VALUES ($ann, $bo, 'hi again')}
  as user $bo allowed {INSERT INTO app.direct_messages (from_id, to_id, body) VALUES ($bo, $ann, 'bye')}
```

## Try it

[Open it in the playground](https://rowstile.dev/playground/#e=blocking): the tables, the policy and the test, in
your browser, with nothing to install. Or try it on a database of your own:
[the steps](../cookbook.md#trying-a-recipe-on-your-own-database) take the files of
[`docs/cookbook/blocking/`](blocking/). CI takes them on every change (`core/tests/cookbook.sh`), and checks that
every line of policy and tests shown here is in those files.

More: [following a relation](../reference/language.md), [the other recipes](../cookbook.md).

# Letting support staff see what a user sees, and emergency access

Two things support teams need, both for a while and both on the record: seeing the app as a customer sees it,
and getting into one row in an emergency.

```authz
type user = app.users
  agent : user = app.support_assignments(customer_id -> agent_id)
  can impersonate = agent

type note = app.notes
  owner  : user = owner_id
  viewer : user shared by share

  can share       = owner
  can view        = owner or viewer
  can break_glass = owner.impersonate
```

- `impersonate` on the user type is a name the runtime asks for. Its holders may call
  `authz.view_as('42', 'ticket 1234')`: the rest of the transaction sees what user 42 sees, read-only, and the
  audit trail keeps who really asked and why.
- Here the holders are the agents assigned to that customer, read from a table. An agent can't view as anyone
  else.
- `break_glass` is the other name. Its holders may give themselves a relation that is shared with users, with
  `authz.break_glass('note', 7, 'viewer', 'INC-7 outage', '1 hour')`: for a day at most, audited, and announced
  on the channel `authz_alerts`.
- `owner.impersonate` follows the note to its owner, then to the people who may impersonate them: the same
  agents.

## Tested

Bo is Ann's support agent; Cy is not:

```authz
test "a customer's agent may view as them, and nobody else"
  user $bo can impersonate user $ann
  user $cy cannot impersonate user $ann
  user $bo cannot impersonate user $cy
  as user $bo allowed {SELECT authz.view_as($ann::text, 'ticket 1234')}
  as user $cy refused {SELECT authz.view_as($ann::text, 'curious')}
```

```authz
test "emergency access: for a while, with a reason"
  user $bo cannot view note $n
  as user $cy refused {SELECT authz.break_glass('note', $n, 'viewer', 'curious', '1 hour')}
  as user $bo allowed {SELECT authz.break_glass('note', $n, 'viewer', 'INC-7 outage', '1 hour')}
  user $bo can view note $n
  as user $bo refused {UPDATE app.notes SET body = 'changed' WHERE id = $n}
```

The tests check who may start a view-as, not what the session then shows: a test line signs in afresh. (What
a key limited to a scope may do can be tested: [API keys limited to some permissions](api-keys-with-scopes.md).)

## Try it

[Open it in the playground](https://rowstile.dev/playground/#e=support-and-emergency-access): the tables, the
policy and the tests, in your browser, with nothing to install. Or try it on a database of your own:
[the steps](../cookbook.md#trying-a-recipe-on-your-own-database) take the files of
[`docs/cookbook/support-and-emergency-access/`](support-and-emergency-access/). CI takes them on every change
(`core/tests/cookbook.sh`), and checks that every line of policy and tests shown here is in those files.

More: [the permissions the runtime asks for](../reference/language.md),
[the audit trail and break glass](../reference/governance.md), [access on request](access-on-request.md),
[the other recipes](../cookbook.md).

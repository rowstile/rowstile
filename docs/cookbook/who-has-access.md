# Who has access to this row, why, and who gave it

Once the rules are in the database, so are the answers to the questions a sharing dialog, a support desk and
an auditor ask. The policy is the one of any shared document:

```authz
type document = app.documents
  owner  : user = owner_id
  viewer : user shared by share

  can share = owner
  can view  = share or viewer
```

Ann asks about her document, the first in `rows.sql`:

```sql
SELECT * FROM authz.who('document', 1, 'view');           -- everyone who may view it
SELECT * FROM authz.list_shares('document', 1);           -- what was shared, with whom, by whom, until when
SELECT * FROM authz.explain('document', 1, 'view', '2');  -- why user 2 may, or what is missing
```

- `authz.who` and `authz.list_shares` answer people who hold `share` on the document, and nobody else: who
  can see a document is itself something to protect.
- `authz.explain` says which part of the permission holds, or what is missing. Without the last argument it
  answers for whoever is signed in.
- A write the rules refuse says why in the same words, and `authz.explain_rule` gives that answer before the
  write is tried.
- Every share, unshare, request, view-as and emergency access is in the audit trail, `authz.audit`, which the
  tables' owner reads and nobody can change.

## Tested

```authz
test "who may see it, and what was shared"
  as user $ann allowed {SELECT authz.share('document', $d, 'viewer', 'user', $bo)}
  as user $ann sees 2 {SELECT FROM authz.who('document', $d, 'view')}
  as user $ann sees 1 {SELECT FROM authz.list_shares('document', $d)}
  as user $bo refused {SELECT FROM authz.who('document', $d, 'view')}
  as user $ann allowed {SELECT authz.unshare('document', $d, 'viewer', 'user', $bo)}
  as user $ann sees 1 {SELECT FROM authz.who('document', $d, 'view')}
```

## Try it

[Open it in the playground](https://rowstile.dev/playground/#e=who-has-access): the tables, the policy and the
tests, in your browser, with nothing to install. Or try it on a database of your own:
[the steps](../cookbook.md#trying-a-recipe-on-your-own-database) take the files of
[`docs/cookbook/who-has-access/`](who-has-access/). CI takes them on every change ([`core/tests/cookbook.sh`](../../core/tests/cookbook.sh)), and
checks that every line of policy and tests shown here is in those files, and that the SQL shown here runs, as Ann.

More: [every function apps call](../reference/app-code.md), [the audit trail](../reference/governance.md),
[the other recipes](../cookbook.md).

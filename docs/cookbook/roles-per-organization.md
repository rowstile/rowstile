# Admin, member and guest roles per organisation, and roles the admins make

What someone may do in an organisation depends on their role there. Three roles are a column of the
membership table; more can be made at run time by the organisation's admins.

```authz
type org = app.orgs
  admin  : user = app.org_members(org_id -> user_id) where {role = 'admin'}
  member : user = app.org_members(org_id -> user_id) where {role in ('admin', 'member')}

  can manage_roles = admin

type document = app.documents
  org    : org  = org_id
  owner  : user = owner_id
  viewer : user shared by share
  roles  : user from org

  can share = owner or org.admin
  can edit  = share or roles
  can view  = edit or viewer or org.member or roles

rules app.documents
  select          : view
  insert          : org.member and owner
  update          : edit
  update owner_id : share
  update org_id   : nobody  -- a document stays in its organisation
  delete          : share
```

- `where {role = 'admin'}` makes a relation from some rows of a table. Admins and members see every document
  of the organisation; admins also edit and share them.
- A guest is in the table with the role `guest`, and no relation reads that: a guest holds only what is
  shared with them.
- `roles : user from org` lets users hold roles that the document's organisation defined. A permission writes
  `roles` where such a role may give it.
- `can manage_roles = admin` says who makes them. An admin creates one with
  `authz.create_role('org', 1, 'document', 'reviewer', ARRAY['view'])`, which returns its id, and gives it like
  a relation: `authz.share('document', 7, 'role:<id>', 'user', 4)`.
- `insert : org.member and owner`: you make a document in your own name, in an organisation you are in.
  `update org_id : nobody` keeps it there. Without it, its owner could move it into any organisation, and every
  member of that one would see it.

## Tested

```authz
test "admins, members and guests"
  user $bo can edit document $mine
  user $ann can edit document $mine
  user $bo can view document $hers
  user $bo cannot edit document $hers
  user $cy cannot view document $hers
  as user $ann allowed {SELECT authz.share('document', $hers, 'viewer', 'user', $cy)}
  user $cy can view document $hers
  user $cy cannot view document $mine
  as user $bo refused {INSERT INTO app.documents (org_id, owner_id, title) VALUES ($globex, $bo, 'Planted')}
  as user $bo refused {UPDATE app.documents SET org_id = $globex WHERE id = $mine}
```

The second test makes a role and gives it in one statement, since giving it needs the id that making it
returns:

```authz
test "a role the admins make"
  as user $bo refused {SELECT authz.create_role('org', $acme, 'document', 'reviewer', ARRAY['view'])}
  as user $ann allowed {SELECT authz.share('document', $d, 'role:' || authz.create_role('org', $acme, 'document', 'reviewer', ARRAY['view']), 'user', $cy)}
  user $cy can view document $d
  user $cy cannot edit document $d
```

## Try it

[Open it in the playground](https://rowstile.dev/playground/#e=roles-per-organization): the tables, the policy and the
tests, in your browser, with nothing to install. Or take the files of
[`docs/cookbook/roles-per-organization/`](roles-per-organization/) (`schema.sql`, `policy.authz`, `tests.authz`) and run `rowstile dev`.
CI applies and tests them on every change (`core/tests/cookbook.sh`), and every line shown here is in those
files.

More: [custom roles](../reference/language.md), [a multi-tenant app](multi-tenant-app.md),
[the other recipes](../cookbook.md).

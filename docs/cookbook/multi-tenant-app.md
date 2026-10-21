# Multi-tenant row-level security: organisations, workspaces, projects

Each organisation is a tenant. Its workspaces and the projects in them are seen by its own people, and by
nobody else. The tenant check is written once, where the types are, so no query has to remember
`WHERE org_id = ...`.

```authz
type org = app.orgs
  member : user = app.org_members(org_id -> user_id)
  admin  : user = app.org_members(org_id -> user_id) where {role = 'admin'}

  can manage = admin
  can view   = manage or member

type workspace = app.workspaces
  org    : org  = org_id
  member : user = app.workspace_members(workspace_id -> user_id)

  can manage = org.manage
  can view   = manage or (member and org.view)

type project = app.projects
  workspace : workspace = workspace_id

  can edit = workspace.view
  can view = edit
```

- A project has no `org_id`. `workspace.view` follows it to its workspace, and `org.manage` and `org.view`
  follow the workspace to its organisation: the tenant is reached through the rows, not copied onto each one.
- `member and org.view`: being put in a workspace gives nothing to someone who isn't in its organisation.
- Admins of the organisation manage every workspace in it; members see the ones they were added to.

```authz
rules app.projects
  select                    : view
  insert                    : workspace.view
  update                    : edit
  update workspace_id after : workspace.view
  delete                    : workspace.manage
```

A project moves only to a workspace its mover may see. Someone in two organisations sees workspaces of both, so
they may move a project from one organisation to the other (the last test shows it). Where a project must
stay in its organisation, write `update workspace_id : nobody`: it then stays in its workspace.

## Proved, not only tested

An invariant says what must never be true, and `rowstile prove` looks for a small world in which it is:

```authz
invariants
  never workspace: view and not org.view
```

    $ rowstile prove policy.authz
    line 45: never workspace: view and not org.view
      ok   holds in every world tried (528 worlds, up to 4 of each type)

The prover reads the policy, and where each relation comes from: `admin` is the rows of `app.org_members`
whose role is `admin`, so every admin is a member, and `can view = member` on the organisation would hold too.
Had admins a table of their own, an admin could be no member: with `can view = member` the prover then finds
one, and says so. `can view = manage or member` says it in the policy, whatever the tables.

## Tested

Bo is in the Design workspace of Acme, Cy is in Acme but not in Design, Dee runs another organisation:

```authz
test "a project is seen in its organisation, by the people of its workspace"
  user $bo can edit project $p
  user $ann can edit project $p
  user $cy cannot view project $p
  user $dee cannot view project $p
  as user $dee sees 0 {SELECT FROM app.projects WHERE workspace_id = $design}
  as user $dee refused {INSERT INTO app.projects (workspace_id, name) VALUES ($design, 'Not mine to make')}
  as user $ann refused {UPDATE app.projects SET workspace_id = $research WHERE id = $p}
```

```authz
test "someone put in a workspace without being in its organisation holds nothing"
  given {INSERT INTO app.workspace_members VALUES ($design, $dee)}
  user $dee cannot view workspace $design
```

Eve is in both organisations, and in a workspace of each:

```authz
test "someone in two organisations may move a project from one to the other"
  user $dee cannot view project $p
  as user $eve allowed {UPDATE app.projects SET workspace_id = $research WHERE id = $p}
  user $dee can view project $p
```

## Try it

[Open it in the playground](https://rowstile.dev/playground/#e=multi-tenant-app): the tables, the policy and the
tests, in your browser, with nothing to install. Or try it on a database of your own:
[the steps](../cookbook.md#trying-a-recipe-on-your-own-database) take the files of
[`docs/cookbook/multi-tenant-app/`](multi-tenant-app/). CI takes them on every change (`core/tests/cookbook.sh`),
and checks that every line of policy and tests shown here is in those files, and that `rowstile prove` prints what
is shown here.

More: [tenants with a key of two columns](tenants.md), [roles in an organisation](roles-per-organization.md),
[invariants and `rowstile prove`](../reference/tools.md), [the other recipes](../cookbook.md).

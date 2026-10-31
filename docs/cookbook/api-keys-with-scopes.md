# API keys limited to some permissions

A person makes a key for a script. The key acts for them, and should do less than they can: read and change
nothing, or add notes and nothing else. A **scope** names what a key is left with, and a key never does more
than its user.

```authz
type project = app.projects
  owner  : user = owner_id
  member : user = app.project_members(project_id -> user_id)

  can edit = owner or member
  can view = edit

type note = app.notes
  project : project = project_id
  author  : user    = author_id

  can edit = author
  can view = project.view

scope inbox = app.notes.insert, project.edit

rules app.notes
  select                       : view
  insert                       : project.edit and author
  update                       : edit
  update project_id, author_id : nobody
  delete                       : edit
```

- `scope inbox = app.notes.insert, project.edit` lists what a key with that scope keeps: one command on one
  table, and the one permission that command's rule asks about. Everything else is gone for it: it can't read a
  note, delete one, or ask whether its user may view something.
- `read` needs no line. It is built in: every `SELECT`, every question, and no write.
- The rules don't mention scopes. A scope only takes away. `insert : project.edit and author` still has to
  hold, so a key adds notes where its user could, in their name.

The app makes a key for whoever is signed in, and shows it once (only its hash is kept):

```sql
SELECT authz.create_api_key('nightly export', 'read');      -- 'ak_...'
SELECT authz.create_api_key('inbox script', 'inbox');
```

A request that brings a key starts its transaction with it, in place of `authz.act_as`:

<!-- not run: ak_... stands for a key the lines above made; the test below checks lines as such a key would run them -->
```sql
SELECT authz.login_key('ak_...');
INSERT INTO app.notes (project_id, author_id, body) VALUES (1, 1, 'from a script');
```

A key that may only insert can't read the row back, so that `INSERT` takes no `RETURNING`. A key made from a
session that is itself limited can't have more scopes than the session.

## Tested

`with scope` after who a line is about checks it as a key limited to that scope would be:

```authz
test "a key does what its scopes say, and no more than its user"
  user $ann can edit note $n
  user $ann with scope read can view note $n
  user $ann with scope inbox cannot view note $n
  as user $ann with scope read sees 1 {SELECT FROM app.notes WHERE id = $n}
  as user $ann with scope read refused {UPDATE app.notes SET body = 'x' WHERE id = $n}
  as user $ann with scope inbox allowed {INSERT INTO app.notes (project_id, author_id, body) VALUES ($p, $ann, 'from a script')}
  as user $ann with scope inbox sees 0 {SELECT FROM app.notes}
  as user $ann with scope inbox refused {DELETE FROM app.notes WHERE id = $n}
  as user $ann with scope read, inbox sees 2 {SELECT FROM app.notes WHERE project_id = $p}
  as user $bo with scope inbox refused {INSERT INTO app.notes (project_id, author_id, body) VALUES ($p, $bo, 'not a member')}
```

The last line is Bo, who isn't in the project: his key is refused where he would be.

## Try it

[Open it in the playground](https://rowstile.dev/playground/#e=api-keys-with-scopes): the tables, the policy and
the test, in your browser, with nothing to install. Or try it on a database of your own:
[the steps](../cookbook.md#trying-a-recipe-on-your-own-database) take the files of
[`docs/cookbook/api-keys-with-scopes/`](api-keys-with-scopes/). CI takes them on every change
([`core/tests/cookbook.sh`](../../core/tests/cookbook.sh)), and checks that every line of policy and tests shown here is in those files, and that
the SQL that makes the keys runs.

More: [API keys, scopes and JWTs](../reference/identity.md),
[keys for services and bots](bots-and-services.md), [the other recipes](../cookbook.md).

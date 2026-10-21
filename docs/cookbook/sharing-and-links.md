# Sharing a row with a person or a team, for a while, and share links

`shared by share` makes a relation people give to each other at run time: whoever holds `share` on a document
gives `viewer` or `editor` to a person, to a team's members, or to whoever holds a link.

```authz
type document = app.documents
  owner  : user = owner_id
  viewer : user, team#member, link shared by share
  editor : user, team#member shared by share

  can share = owner
  can edit  = share or editor
  can view  = edit or viewer
```

- The words after the colon say who a relation may be given to: `user`, `team#member` (a team's members),
  `link` (whoever holds a link).
- `shared by share` names the permission that giving it takes. Here only the owner shares; write
  `can share = owner or editor` to let editors pass it on.
- The app shares with `authz.share()`, signed in as the person who shares, and the database checks them. A
  share can end, and start later:

```authz
  as user $ann allowed {SELECT authz.share('document', $d, 'viewer', 'user', $bo)}
  as user $ann allowed {SELECT authz.share('document', $d, 'editor', 'team', $eng, 'member')}
  as user $ann allowed {SELECT authz.share('document', $d, 'viewer', 'user', $bo, '', now() + interval '1 week', now() + interval '1 day')}
```

The end comes first, then the start: the last share holds from tomorrow until a week from now.

- `authz.create_link('document', 7, 'viewer')` returns a token. A request that carries it sets
  `authz_ctx.links` to it for its transaction, and holds what the link gives
  ([using it from app code](../reference/app-code.md)).

## Tested

```authz
test "sharing with a person and with a team"
  user $bo cannot view document $d
  as user $ann allowed {SELECT authz.share('document', $d, 'viewer', 'user', $bo)}
  user $bo can view document $d
  user $bo cannot edit document $d
  as user $bo refused {SELECT authz.share('document', $d, 'editor', 'user', $bo)}
  user $cy can edit document $d
  as user $cy refused {DELETE FROM app.documents WHERE id = $d}
```

Ann's link line also presents the token, as a request that carries it would (`set_config(..., true)` lasts
until the test ends):

```authz
test "a share that starts later, and a link"
  user $bo cannot view document $d
  as user $ann sees 1 {SELECT FROM authz.list_shares('document', $d) WHERE starts_at = now() + interval '1 day' AND expires_at = now() + interval '1 week'}
  as user $bo refused {SELECT authz.create_link('document', $d, 'viewer')}
  as user $ann allowed {SELECT set_config('authz_ctx.links', authz.create_link('document', $d, 'viewer'), true)}
  user $bo can view document $d
  anyone can view document $d
```

## Try it

[Open it in the playground](https://rowstile.dev/playground/#e=sharing-and-links): the tables, the policy and the
tests, in your browser, with nothing to install. Or try it on a database of your own:
[the steps](../cookbook.md#trying-a-recipe-on-your-own-database) take the files of
[`docs/cookbook/sharing-and-links/`](sharing-and-links/). CI takes them on every change (`core/tests/cookbook.sh`),
and checks that every line of policy and tests shown here is in those files.

More: [shares](../reference/language.md), [listing and taking back shares and links](../reference/app-code.md),
[the other recipes](../cookbook.md).

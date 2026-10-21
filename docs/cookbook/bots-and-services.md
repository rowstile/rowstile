# Permissions for services and bots, not only users

A `principal` type signs in as itself. A bot is a row of `app.services`, with API keys of its own, and
relations name it as they name a user.

```authz
type service = app.services principal
  owner : user = owner_id
  can manage_keys = owner

type channel = app.channels
  member : user    = app.channel_members(channel_id -> user_id)
  bot    : service = app.channel_bots(channel_id -> service_id)

  can read = member or bot
  can post = bot

type post = app.posts
  channel  : channel = channel_id
  from_bot : service = bot_id

rules app.posts
  select : channel.read
  insert : channel.post and from_bot
```

- `principal` after the table lets its rows sign in. The backend signs a bot in with
  `authz.act_as('service', id)`, or the bot brings an API key (`authz.login_key`).
- `can manage_keys = owner` says who may make and revoke a service's keys: `manage_keys` is a name the runtime
  asks for.
- `bot : service` is a relation to services, read from a link table like any other. A bot posts where it was
  added, and nowhere else.
- `insert : channel.post and from_bot`: the post names the bot that writes it, so one bot can't post as another.

## Tested

```authz
test "a bot posts where it was added, as itself"
  service $weather cannot post channel $c
  given {INSERT INTO app.channel_bots VALUES ($c, $weather)}
  service $weather can post channel $c
  as service $weather refused {INSERT INTO app.posts (channel_id, bot_id, body) VALUES ($c, $other, 'as another bot')}
  as service $other refused {INSERT INTO app.posts (channel_id, bot_id, body) VALUES ($c, $other, 'not added here')}
  user $ann can manage_keys service $weather
  user $bo cannot manage_keys service $weather
```

## Try it

[Open it in the playground](https://rowstile.dev/playground/#e=bots-and-services): the tables, the policy and the
test, in your browser, with nothing to install. Or try it on a database of your own:
[the steps](../cookbook.md#trying-a-recipe-on-your-own-database) take the files of
[`docs/cookbook/bots-and-services/`](bots-and-services/). CI takes them on every change (`core/tests/cookbook.sh`),
and checks that every line of policy and tests shown here is in those files.

More: [principals other than users, API keys and scopes](../reference/identity.md),
[the other recipes](../cookbook.md).

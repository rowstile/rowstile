# Rules that depend on the row: read-only announcement channels

`{SQL}` is a condition on the row, written in SQL. Members read a channel and post in it; in an announcement
channel only its admins post.

```authz
type channel = app.channels
  member : user = app.channel_members(channel_id -> user_id)
  admin  : user = app.channel_members(channel_id -> user_id) where {admin}

  can read = member
  can post = member and ({not announce} or admin)

type post = app.posts
  channel : channel = channel_id
  author  : user    = author_id

rules app.posts
  select : channel.read
  insert : channel.post and author
```

- `{not announce}` reads the channel's own column. Parentheses say what goes first where `and` meets `or`.
- `where {admin}` makes `admin` from the rows of the membership table whose `admin` column is true.
- `insert : channel.post and author`: you may post in that channel, and the post names you as its author.

The same works for any state a row has: `{not archived}`, `{published}`, `{status = 'draft'}`.

## Tested

```authz
test "in an announcement channel, members read and only admins post"
  user $bo can read channel $news
  user $bo cannot post channel $news
  user $ann can post channel $news
  as user $bo refused {INSERT INTO app.posts (channel_id, author_id, body) VALUES ($news, $bo, 'hi')}
  as user $bo allowed {INSERT INTO app.posts (channel_id, author_id, body) VALUES ($chat, $bo, 'hi')}
  as user $bo refused {INSERT INTO app.posts (channel_id, author_id, body) VALUES ($chat, $ann, 'as Ann')}
```

## Try it

[Open it in the playground](https://rowstile.dev/playground/#e=conditions-on-the-row): the tables, the policy and
the test, in your browser, with nothing to install. Or try it on a database of your own:
[the steps](../cookbook.md#trying-a-recipe-on-your-own-database) take the files of
[`docs/cookbook/conditions-on-the-row/`](conditions-on-the-row/). CI takes them on every change
([`core/tests/cookbook.sh`](../../core/tests/cookbook.sh)), and checks that every line of policy and tests shown here is in those files.

## What it costs

A condition on the row's own columns is written into the rule as it is. One that reads other rows (a
subquery, a function) is called for each row the rule checks, which costs more on large reads than the same
test written as a relation ([Speed and limits](../reference/limits.md)).

More: [conditions](../reference/language.md), [bots that post](bots-and-services.md),
[the other recipes](../cookbook.md).

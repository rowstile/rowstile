# Messenger

A WhatsApp-style messaging app, built to show what rowstile takes off an application's hands. It has
direct chats and groups, owners and admins, announcement groups, invite links, blocking, message editing
and deleting for everyone, read receipts, bots that post with their own API keys, and live updates.

Every rule about who may do what lives in one file, [`db/policy.authz`](db/policy.authz) (about 130 lines).
rowstile turns it into row-level security on the app's tables. The backend
([`backend/app/main.py`](backend/app/main.py)) has **no permission checks at all**: it signs each
transaction in as the person asking, runs plain SQL, and turns the database's refusals into HTTP errors.

![A group: its owner's controls come from authz.perms; a bot posts as itself](docs/group.png)

![An announcement group: the member can't post, and "why?" shows the database's explanation](docs/why.png)

![A direct chat where one of the two blocked the other: neither can post, and "why?" shows "not blocked" fails](docs/blocked.png)

```
docker compose up -d --build          # the app on http://localhost:8001 (Postgres and rowstile, built from this repository)
./test.sh                             # the API tests: the database in Docker, the tests on the host
(cd frontend && npm ci && npm test)   # the web app's tests
```

For development, the database in Docker and the rest on the host:

```
docker compose up -d --wait db                # the database alone, on localhost:25433 (its owner: db/owner.sql)
export MS_ADMIN_URL=postgresql://ms_owner:ms_owner@localhost:25433/messenger MS_APP_PASSWORD=ms_app
cd backend
uv run python ../db/migrate.py                # the migrations, as the tables' owner
uv run uvicorn app.main:app --port 8001       # the API, as ms_app (MS_DATABASE_URL defaults to this database)
```

and in another terminal, `cd frontend && npm ci && npm run dev`: the web app on `http://localhost:5173`, which
sends `/api` to the backend. While changing the policy, `rowstile dev` (with `MS_ADMIN_URL` set as above;
`rowstile.toml` says the rest) applies it on every save, runs its tests and rewrites the client. The migrations
set that database up, so mark it as a development database once first: `rowstile push --development`.

## The rules, and where they are

| What the app does | How the policy says it |
|---|---|
| Only members read a chat | `can read = member or bot`, and `rules ms.messages select : read` |
| New members don't see what was said before they joined; a bot, which isn't a member, reads the whole chat | `message.read = chat.read and {seq > coalesce(ms.joined_seq(chat_id), 0)}` (by the message's number: a clock that steps back refuses nothing; `ms.joined_seq` is null for a bot, so it reads from the first message) |
| Owners and admins manage a group | `admin : user = ms.members(chat_id -> user_id) where {role in ('admin', 'owner')}`, `can manage = admin and {kind = 'group'}` |
| Announcement groups: only admins post | `can post = (member and not blocked and ({not admins_only} or admin)) or bot` |
| Blocking: neither can write to the other in their direct chat | `blocked : user = ms.direct_blocks(chat_id -> user_id)`, and `not blocked` in `post` |
| ...and someone who blocked you can't be added to a chat with you | `rules ms.members insert : ... and not person.has_blocked` |
| A direct chat stays two people | `add_members = ... or (creator and {kind = 'direct'} and {(select count(*) ...) < 2})`; a rule checks each row against the table as the statement found it, so for a statement that adds several at once, the schema counts too (`ms.pair_direct`, [migration 0064](db/migrations/0064_counts_held_by_the_schema.sql)) |
| Nobody demotes or removes the owner, nor makes another; the owner doesn't leave (they delete the group) | `update role : chat.manage and {role <> 'owner'}`, `update role after : {role <> 'owner'}`, `delete : (person or chat.manage) and {role <> 'owner'}`; and one owner a chat in the schema, for a group set up by one statement (`members_one_owner`, migration 0064) |
| Edit your own messages for 15 minutes | `can edit = sender and {not deleted and created_at > now() - interval '15 minutes'}`, and `update edited_at : edit`: only an edit marks a message edited |
| Delete for everyone: yours, or anyone's if you're an admin; no undelete | `can remove = sender or chat.manage`, `update deleted after : {deleted}` |
| Invite links anyone can use for a week | `invitee : link shared by invite`, `can join = (invitee and {kind = 'group'}) or manage`; the backend calls `authz.create_link` with an end a week away (`MS_INVITE_DAYS`), and `authz.list_links` and `authz.revoke_link` so admins see the links and turn one off. Admins may join without a link, so the link's address also names its chat (`/join/<token>?chat=7`): an admin who opens it is shown the group |
| Bots post as themselves, only where an admin added them | `type bot = ms.bots principal where {active}`, `bot : bot = ms.chat_bots(...)`, `from_bot` in the insert rule |
| Only a bot's owner makes its keys | `can manage_keys = owner` on the bot type; the backend calls `authz.create_api_key(..., 'bot', id)` |
| Messages are numbered per chat | `type message = ms.messages (chat_id, seq)`: a composite key; the API asks `authz.can('message', '(7,42)', 'edit')` |

Each row of this table is checked in [`db/tests/rules.authz`](db/tests/rules.authz): each test makes the people
and chats it needs, checks who may do what (as the app, through row-level security), and rolls back. `rowstile
test` runs them: 71 checks, in about a second.

## What the backend doesn't have to do

- **No checks before queries.** `POST /api/chats/{id}/messages` is an `INSERT`. If you may not post
  there (not a member, blocked, an announcement group), row-level security refuses it, and the API
  answers 403.
- **No filtering after queries.** `GET /api/chats` is a join of `ms.chats` and your membership row; it
  returns only the chats you may read. A chat you're not in answers 404, as if it didn't exist.
- **No "why can't I?" logic.** When the database refuses a write, its error says which rule refused it and
  what is missing. The API passes that on (`refusal(error)` from the generated client), and an update that
  changed nothing asks for the same (`tx.authz.expect`). The web app shows it behind a "why?" link:

  ```
  no   insert : chat.post and ((sender and {bot_id is null}) or (from_bot and {sender_id is null}))  (line 105)
    no   chat.post
      no   user 5cf5… does not hold post on chat 16
        chat.post = (member and not blocked and ({not admins_only} or admin)) or bot
        no   (member and not blocked and ({not admins_only} or admin))
          yes  member
          yes  not blocked
          no   ({not admins_only} or admin)
        no   bot
    yes  ((sender and {bot_id is null}) or (from_bot and {sender_id is null}))
  ```
- **No permission model in the UI.** The chat's `perms` come from `authz.perms`, and buttons show or hide
  by them. The database checks again when you press them.
- **No bot authentication.** A bot sends `Authorization: Bearer ak_...`; the backend calls
  `authz.login_key`, and the database knows which bot it is (`authz.principal()`).
- **Live updates that can't leak.** A trigger announces "chat N changed"
  (`NOTIFY ms_events`). The backend asks the database once which of the connected people may read chat N
  (`authz.who_among`), and only then passes the number on. The browser refetches through the API, which row-level
  security filters. A WebSocket never carries a message.

## What rowstile caught while building it

- **`authz.lint()` flagged the blocking view.** The view `ms.direct_blocks` was readable by the app role,
  and views run with their owner's rights, so they bypass row-level security. The migration now revokes it:
  only the policy reads it.
- **Rule conditions run as the app role.** "Never add someone who blocked you" first read `ms.blocks` in
  a `{condition}`. It saw nothing, because a person may only see their own blocks. As a relation
  (`has_blocked`, followed with `person.has_blocked`), the policy reads it with its own rights.
- **The plain `update` rule holds before and after the change.** "Deleted for everyone" made the message
  fail `remove` if `remove` required "not deleted yet". So `remove` doesn't; `update deleted after :
  {deleted}` forbids undeleting.

## Layout

- `db/policy.authz` the rules; `db/migrations/` the tables (plain data integrity) and the policy's migrations,
  which `rowstile migrate` writes from it; `db/migrate.py` applies the migrations not applied yet, and with
  `--client` rewrites the generated client (`backend/app/authz_client.py`, from `rowstile client py`)
- `backend/` FastAPI: `main.py` the API, `db.py` transactions signed in as a person or a bot, `auth.py`
  passwords and sessions, `events.py` live updates, `tests/test_api.py`
- `frontend/` React: the chat list, conversations, group info, settings (profile, bots, blocked people)
- `check_public_surface.py`: the app uses only rowstile's public functions, never its internals

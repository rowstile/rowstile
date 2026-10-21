# rowstile and checks in app code

Most apps start with an `if` in each handler: is this the owner, is this an admin. Libraries such as CASL,
Casbin and Pundit give those checks a place and a vocabulary. For a few roles it is enough, and it is the
simplest thing that works. This page says where it gets hard, and what changes when the database enforces
the rules instead.

The short version for every alternative is on [rowstile and the alternatives](../comparison.md).

## Where it gets hard

**Every handler must remember.** A check lives in the code path that someone wrote it into. The export
somebody adds next year, the background job, the admin script and the second service on the same database
each need it again. The one that forgets shows everything, and nothing fails to say so.

**A list is the rule written twice.** `can(user, "view", document)` answers for one document. "The documents
this user may see, by name, page 3" can't call it for every row, so the rule is written a second time as a
`WHERE`, and the two must be kept the same by hand. When access is shared or inherited (a folder's editors,
a team inside a team) that `WHERE` is the hard part of the whole feature.

**The rule is spread out.** Who may edit a document is the sum of the checks in every handler that touches
one. Reading it means reading them all, and a review of a change to one of them can't say who gains access.

## With the rules in the database

The handler has no check. This is the conformance app's route for editing a note, with FastAPI and
SQLAlchemy:

```python
    @app.patch("/notes/{note_id}")
    async def edit_note(note_id: int, b: Body) -> dict[str, int]:
        async with Session.begin() as s:
            note = await s.get(Note, note_id)
            if note is None:
                raise NotFound("app.notes", note_id)
            note.body = b.body  # an update the rules may refuse: StaleDataError -> 403 with the reason
        return {"id": note_id}
```

A note the user can't see isn't found: Postgres leaves it out of the read. One they see and may not edit is
refused by Postgres when the update runs, and the SDK answers 403 with the rule that said no. The list has
no filter either:

```python
    @app.get("/notes")
    async def notes() -> list[int]:
        async with Session() as s:
            return sorted((await s.scalars(select(Note.id))).all())
```

The rule is in one file, where a test can name it (`user 2 cannot edit note 1`) and a review can say what a
change to it does. The part of that app's policy about notes:

```authz
type note = app.notes
  project : project = project_id
  author  : user    = author_id

  can edit = author or project.owner
  can view = project.view

rules app.notes
  select : view
  insert : project.edit and author
  update : edit
  delete : edit
```

## What it costs

- **Postgres only**, and one database: the rules read rows.
- **The app connects as a role of its own**, not as the tables' owner, and each transaction says who is
  signed in. The SDKs do that; it is a change to how the app opens its connections.
- **A rule change is a migration**, not a deploy of code alone.
- **Rules about something other than rows** (who may call an endpoint that touches no table, a rate limit, a
  feature flag) stay in app code. rowstile doesn't replace those checks.
- **A new tool**, in beta, with one maintainer, which nobody outside has audited
  ([how it is checked](../how-it-is-checked.md)).

## When checks in app code are the better choice

- **A small app with a few roles** and no sharing between users: an `if` is easier to read than any tool.
- **One code path to the data**, and it will stay one.
- **The rules aren't about rows**, or the data isn't in Postgres.

## Try it

[Getting started](../getting-started.md) takes a schema to a tested policy in about fifteen minutes, and the
[stack pages](../stacks/README.md) show the app's side for FastAPI, Next.js and plain SQL.

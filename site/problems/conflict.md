# Conflict (409)

`https://rowstile.dev/problems/conflict` is the `type` of the problem body ([RFC 9457](https://www.rfc-editor.org/rfc/rfc9457))
the SDKs answer with when the database turns down a change because of where things are now: a move that would
put a folder inside one of its own subfolders. The same move may work once the tree is different, so it is a
conflict, not a malformed request.

```json
{
  "type": "https://rowstile.dev/problems/conflict",
  "title": "Conflict",
  "status": 409,
  "detail": "folder 1 cannot be moved inside itself",
  "code": "AZ713"
}
```

- `detail`: the database's words, which name the object.
- `code`: [AZ713](../../docs/errors/AZ713.md), moved inside itself.

`rowstile.fastapi` answers 409 too when an ORM update matched no row though the rules allow it: the row changed
since it was read (a version counter, SQLAlchemy's `version_id_col`). Read it again, then try again. This one
has no `code`, since the database turned nothing down:

```json
{
  "type": "https://rowstile.dev/problems/conflict",
  "title": "Conflict",
  "status": 409,
  "detail": "the row changed since it was read, and the rules allow the change: read it again"
}
```

Where it comes from: `rowstile.fastapi` ([FastAPI](../../docs/stacks/fastapi.md)), `route()` and `action()` in
`@rowstile/next` ([Next.js](../../docs/stacks/nextjs.md)) and `problemOf(e)` for any other framework
([Node](../../docs/stacks/node.md)).

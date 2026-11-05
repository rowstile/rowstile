# Bad argument (400)

`https://rowstile.dev/problems/bad-argument` is the `type` of the problem body ([RFC 9457](https://www.rfc-editor.org/rfc/rfc9457))
the SDKs answer with when the database says a call lacks something it needs, or has a value out of range: an
access request without a reason, a negative page size. It is the user's to fix, not the server's failure.

```json
{
  "type": "https://rowstile.dev/problems/bad-argument",
  "title": "Bad Request",
  "status": 400,
  "detail": "say why you need it",
  "code": "AZ710"
}
```

- `detail`: the database's words, which say what is missing or wrong.
- `code`: [AZ710](../../docs/errors/AZ710.md), a missing or wrong argument.

Where it comes from: every SDK ([each one's calls](../../docs/stacks/README.md#problem-details)). In Python and TypeScript: `rowstile.fastapi`
([FastAPI](../../docs/stacks/fastapi.md)), `route()` and `action()` in `@rowstile/next`
([Next.js](../../docs/stacks/nextjs.md)) and `problemOf(e)` for any other framework
([Node](../../docs/stacks/node.md)). The routes `authzRoutes()` makes for `@rowstile/react` answer with it too:
`POST request` without a reason. `useAccessRequest` then fails with the database's words.

# Not signed in (401)

`https://rowstile.dev/problems/not-signed-in` is the `type` of the problem body ([RFC 9457](https://www.rfc-editor.org/rfc/rfc9457))
the SDKs answer with when the database says the request needs someone signed in: a visitor who hasn't signed in
asks for access or makes an API key, or a login with an API key or a token is refused. Signing in is the user's
to do, not the server's failure.

```json
{
  "type": "https://rowstile.dev/problems/not-signed-in",
  "title": "Unauthorized",
  "status": 401,
  "detail": "sign in first",
  "code": "AZ714"
}
```

- `detail`: the database's words: "sign in first", "invalid API key", "token expired or not yet valid".
- `code`: [AZ714](../../docs/errors/AZ714.md), a call that needs someone signed in, or
  [AZ703](../../docs/errors/AZ703.md), a login refused.

The app sends no `WWW-Authenticate` header with it: how people sign in is the app's. A query in a transaction
that never signed in at all is the app's bug ([AZ701](../../docs/errors/AZ701.md)), not this: it stays an error,
a 500.

Where it comes from: every SDK ([each one's calls](../../docs/stacks/README.md#problem-details)). In Python and TypeScript: `rowstile.fastapi`
([FastAPI](../../docs/stacks/fastapi.md)), `route()` and `action()` in `@rowstile/next`
([Next.js](../../docs/stacks/nextjs.md)) and `problemOf(e)` for any other framework
([Node](../../docs/stacks/node.md)). The routes `authzRoutes()` makes for `@rowstile/react` answer with it too:
`POST request` from someone not signed in. `useAccessRequest` then fails with the database's words.

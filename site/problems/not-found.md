# Not found (404)

`https://rowstile.dev/problems/not-found` is the `type` of the problem body ([RFC 9457](https://www.rfc-editor.org/rfc/rfc9457))
the SDKs answer with when a row isn't there, or whoever the transaction acts for can't see it. Both get the
same answer. So does a call the database says names something that isn't there: a share with someone who
doesn't exist, an API key of yours that isn't there.

```json
{
  "type": "https://rowstile.dev/problems/not-found",
  "title": "Not Found",
  "status": 404,
  "detail": "app.files 11 not found"
}
```

- `detail`: the row, by its table and key. For a call the database said no to, its words: "there is no user 99".
- `code`: [AZ708](../../docs/errors/AZ708.md), only for a call the database said no to.

Where it comes from: every SDK ([each one's calls](../../docs/stacks/README.md#problem-details)), for a hidden row and for AZ708 alike. In Python and
TypeScript, `NotFound.problem()` is it; `rowstile.fastapi` answers with it ([FastAPI](../../docs/stacks/fastapi.md)),
and so do `route()` and `action()` in `@rowstile/next` ([Next.js](../../docs/stacks/nextjs.md)) and `problemOf(e)`
for any other framework ([Node](../../docs/stacks/node.md)). A write the user may not make, on a
row they can see, is [Refused](refused.md) instead.

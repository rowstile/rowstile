# Refused (403)

`https://rowstile.dev/problems/refused` is the `type` of the problem body ([RFC 9457](https://www.rfc-editor.org/rfc/rfc9457))
the SDKs answer with when the database refused a write: a rule stopped an insert, an update or a delete, and
rowstile said which rule and why.

```json
{
  "type": "https://rowstile.dev/problems/refused",
  "title": "Forbidden",
  "status": 403,
  "detail": "the database's message",
  "table": "app.files",
  "command": "update",
  "why": ["the lines of the explanation"],
  "code": "AZ709"
}
```

- `table` and `command`: the rule that refused it. The table is named as the policy names it, with its
  schema (`public.Note` for a Prisma model `Note`), whichever rule refused: a table's, or a column's. The
  command is `insert`, `update` or `delete`, or `select` for a row that was written and may not be read back.
  Both are `null` for a refusal that is no rule's: a share by someone who may not share.
- `why`: the reason, as the database explained it (empty when it gave none).
- `code`: [AZ709](../../docs/errors/AZ709.md), a write refused by a rule. Another refusal has the database's
  own code: [AZ705](../../docs/errors/AZ705.md) for a share.

Where it comes from: every SDK ([each one's calls](../../docs/stacks/README.md#problem-details)). In Python and TypeScript, `Refused.problem()` is it;
`rowstile.fastapi` answers with it ([FastAPI](../../docs/stacks/fastapi.md)), and so do `route()` and `action()` in
`@rowstile/next` ([Next.js](../../docs/stacks/nextjs.md)) and `problemOf(e)` for any other framework
([Node](../../docs/stacks/node.md)).

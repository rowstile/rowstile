# @rowstile/prisma

[rowstile](https://rowstile.dev) is a policy language for PostgreSQL. You write who may see and change each
row in one file, and it becomes row-level security: the database filters every read and refuses every write
the rules don't allow, whatever the code asks.

This package is rowstile for Prisma. `signedIn(adapter)` signs every transaction Prisma begins in as the
request's user. `authz()` is a client extension: an update or delete of a row the user can't see is
`NotFound`, of one they may not change `Refused` with the database's reason, and `db.$authz` asks the
questions (`can`, `ids`, `permsOf`, `share`). Prisma 7, with a driver adapter.

```sh
# @next on each: the newest pre-release (until 0.1.0 a plain install gets it too)
npm install @rowstile/client@next @rowstile/prisma@next
npm install --save-dev rowstile@next      # the command: rowstile dev, rowstile migrate
```

```ts
// src/db.ts
import { PrismaPg } from "@prisma/adapter-pg";
import pg from "pg";
import { authz, signedIn } from "@rowstile/prisma";
import "./authz.gen.ts";                              // the policy's names, for the SDK's types

const url = process.env.ROWSTILE_APP_URL;
export const pool = new pg.Pool({ connectionString: url, max: Number(process.env.PG_POOL_MAX ?? 5) });
export const db = new PrismaClient({ adapter: signedIn(new PrismaPg(pool), { user: requestUser }) }).$extends(authz());
```

`ROWSTILE_APP_URL` is the app's own connection, as the role the policy names. It is never the owner's URL,
which Prisma migrates with: row-level security doesn't apply to a table's owner.

Then the code has no checks. The database filters what a query reads:

```ts
  const notes = await db.note.findMany({ select: { id: true, body: true }, orderBy: { id: "asc" } });
```

and a query by permission is one call:

```ts
  const ids = await db.$authz.ids("project", "edit", Number);
  const projects = await db.project.findMany({ where: { id: { in: ids } }, select: { id: true }, orderBy: { id: "asc" } });
```

## Good to know

- Use the client `$extends(authz())` returns, and only that one.
- `$transaction([...])` is refused: Prisma starts an array's transaction from whichever request came first.
  Use `$transaction(async (tx) => ...)`. Inside it, why a write was refused is asked through the transaction:
  it needs no second connection.
- A `create` reads its row back, so it needs the select rule too. A refusal there is `Refused` naming it.
- A refusal's `table` is the table as the policy names it, with its schema: `public.Note` for a model `Note`.
  `db.$authz.tableName("Note")` gives that name.
- Policy changes ship as Prisma migrations: `tool = "prisma"` in `rowstile.toml`, then `npx rowstile migrate`.

## More

- [Next.js with Prisma](https://rowstile.dev/stacks/nextjs): the whole setup, step by step, from an app the tests run.
- [The TypeScript SDK](https://rowstile.dev/sdk/typescript): every package, and the traps they handle.
- [Getting started](https://rowstile.dev/getting-started): a first policy, step by step.
- [Source and issues](https://github.com/rowstile/rowstile).

The other packages:

| package | for |
|---|---|
| [`@rowstile/client`](https://www.npmjs.com/package/@rowstile/client) | who a transaction acts for, the errors, the runtime's calls |
| [`@rowstile/pg`](https://www.npmjs.com/package/@rowstile/pg) | node-postgres |
| [`@rowstile/postgres`](https://www.npmjs.com/package/@rowstile/postgres) | postgres.js |
| [`@rowstile/drizzle`](https://www.npmjs.com/package/@rowstile/drizzle) | Drizzle ORM |
| [`@rowstile/next`](https://www.npmjs.com/package/@rowstile/next) | Next.js: route handlers, server actions, caches |
| [`@rowstile/react`](https://www.npmjs.com/package/@rowstile/react) | React: hooks and a share dialog |
| [`@rowstile/vitest`](https://www.npmjs.com/package/@rowstile/vitest) | Vitest: matchers, a database per worker |
| [`@rowstile/jest`](https://www.npmjs.com/package/@rowstile/jest) | Jest (preview): matchers, a database per worker |

rowstile is in beta: names may still change before 1.0. Apache-2.0.

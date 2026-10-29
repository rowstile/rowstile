# @rowstile/next

[rowstile](https://rowstile.dev) is a policy language for PostgreSQL. You write who may see and change each
row in one file, and it becomes row-level security: the database filters every read and refuses every write
the rules don't allow, whatever the code asks.

This package is rowstile for Next.js (App Router). Importing it keeps signed-in reads out of Next's caches.
`route(handler)` answers a refusal with 403 and a hidden row with 404 (and what a call names that isn't there
404, a missing or wrong argument 400, a call that needs someone signed in 401, a move inside itself 409).
`action(fn)` gives a server action's
refusal back as a value. `authzRoutes()` is what the React kit calls, and `checkAtStart()` stops a server
whose connection skips row-level security. It goes with a driver package, most often `@rowstile/prisma`.

```sh
# @next on each: the newest pre-release (until 0.1.0 a plain install gets it too)
npm install @rowstile/next@next @rowstile/prisma@next
npm install --save-dev rowstile@next      # the command: rowstile dev, rowstile migrate
```

A route handler with no checks: a hidden note is 404, one the user may not edit 403 with the reason.

```ts
import { route } from "@rowstile/next";
import { db } from "@/db";

type Params = { params: Promise<{ id: string }> };

export const PATCH = route(async (req: Request, { params }: Params) => {
  const id = Number((await params).id);
  const { body } = (await req.json()) as { body: string };
  await db.note.update({ where: { id }, data: { body } });
  return Response.json({ id });
});
```

A server action: Next.js hides a thrown error's message, so the refusal comes back as `{ ok: false, problem }`.

```ts
// app/actions.ts
import { action } from "@rowstile/next";

export const renameNote = action(async (id: number, body: string) => {
  await db.note.update({ where: { id }, data: { body } });
  return id;
});
```

At start-up:

```ts
// instrumentation.ts
import { checkAtStart } from "@rowstile/next";

export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") await checkAtStart((await import("./src/db.ts")).db.$authz);
}
```

## Good to know

- Before a transaction signs in as someone, it calls Next's `connection()`: the render is dynamic, and a
  signed-in read inside `"use cache"` or `unstable_cache` fails instead of being cached for the next user.
  Reads as nobody may be cached.
- `authzRoutes({ calls, changes })` in `app/api/authz/[...authz]/route.ts` serves `@rowstile/react`:
  permissions for a list, shares, access requests, live updates.

## More

- [Next.js with Prisma](https://rowstile.dev/stacks/nextjs): the whole setup, step by step, from an app the tests run.
- [The TypeScript SDK](https://rowstile.dev/sdk/typescript): every package, and the traps they handle.
- [Getting started](https://rowstile.dev/getting-started): a first policy, step by step.
- [Source and issues](https://github.com/rowstile/rowstile).

The other packages:

| package | for |
|---|---|
| [`@rowstile/client`](https://www.npmjs.com/package/@rowstile/client) | who a transaction acts for, the errors, the runtime's calls |
| [`@rowstile/prisma`](https://www.npmjs.com/package/@rowstile/prisma) | Prisma |
| [`@rowstile/pg`](https://www.npmjs.com/package/@rowstile/pg) | node-postgres |
| [`@rowstile/postgres`](https://www.npmjs.com/package/@rowstile/postgres) | postgres.js |
| [`@rowstile/drizzle`](https://www.npmjs.com/package/@rowstile/drizzle) | Drizzle ORM |
| [`@rowstile/react`](https://www.npmjs.com/package/@rowstile/react) | React: hooks and a share dialog |
| [`@rowstile/vitest`](https://www.npmjs.com/package/@rowstile/vitest) | Vitest: matchers, a database per worker |
| [`@rowstile/jest`](https://www.npmjs.com/package/@rowstile/jest) | Jest (preview): matchers, a database per worker |

rowstile is in beta: names may still change before 1.0. Apache-2.0.

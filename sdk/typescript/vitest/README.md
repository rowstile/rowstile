# @rowstile/vitest

[rowstile](https://rowstile.dev) is a policy language for PostgreSQL. You write who may see and change each
row in one file, and it becomes row-level security: the database filters every read and refuses every write
the rules don't allow, whatever the code asks.

This package is for an app's own tests, with Vitest 4 or 5 (the matchers work with Jest too). `toBeRefused`
and `toBeNotFound` say what a write should have been. `asUser(who, fn)` runs code as someone.
`databasePerWorker(url)` copies the migrated test database, with its policy, once for each worker, so tests
that write don't meet each other.

```sh
# @next on each: the newest pre-release (until 0.1.0 a plain install gets it too)
npm install --save-dev @rowstile/vitest@next rowstile@next
```

```ts
// tests/setup.ts
import { expect } from "vitest";
import { matchers } from "@rowstile/vitest";

expect.extend(matchers);
```

Then a test says who, what, and what the database should answer: the command it refused and the permission
that was missing, or that the row isn't there for this user.

```ts
  await expect(actingAs("3", () => db.$transaction((tx) => tx.note.update({ where: { id: 1 }, data: { body: "x" } }))))
    .rejects.toBeRefused("update", "note.edit");
  await expect(actingAs("2", () => db.note.delete({ where: { id: 1 } }))).rejects.toBeNotFound();
```

A database per worker:

```ts
  const worker = await databasePerWorker(tests!, { appUrl: appTests.toString() });
```

## Good to know

- `asUser(who, fn)` is `actingAs` from `@rowstile/client`, under the name tests read best.
- The policy has tests of its own, in the policy's language (`rowstile test`): who sees what, who is
  refused. These matchers are for the app's code on top of it.

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
| [`@rowstile/next`](https://www.npmjs.com/package/@rowstile/next) | Next.js: route handlers, server actions, caches |
| [`@rowstile/react`](https://www.npmjs.com/package/@rowstile/react) | React: hooks and a share dialog |

rowstile is in beta: names may still change before 1.0. Apache-2.0.

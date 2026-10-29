# @rowstile/jest

**A preview**: this package may change in any release, and it is not part of what 1.0 will freeze.

[rowstile](https://rowstile.dev) is a policy language for PostgreSQL. You write who may see and change each
row in one file, and it becomes row-level security: the database filters every read and refuses every write
the rules don't allow, whatever the code asks.

This package is for an app's own tests, with Jest 30. `toBeRefused` and `toBeNotFound` say what a write should
have been. `asUser(who, fn)` runs code as someone. `databasePerWorker(url)` copies the migrated test database,
with its policy, once for each Jest worker, so tests that write don't meet each other. It is
`@rowstile/vitest`'s code, with Jest's types for the matchers.

```sh
# @next on each: the newest pre-release (until 0.1.0 a plain install gets it too)
npm install --save-dev @rowstile/jest@next rowstile@next
```

```ts
// tests/setup.ts
import { expect } from "@jest/globals";
import { matchers } from "@rowstile/jest";

expect.extend(matchers);
```

Name it in Jest's config, `setupFilesAfterEnv`. Then a test says who, what, and what the database should
answer: the command it refused and the permission that was missing, or that the row isn't there for this user.

```ts
    await expect(asUser("2", () => a.query("INSERT INTO app.notes (project_id, author_id, body) VALUES (3, 2, 'hi')")))
      .rejects.toBeRefused("insert", "project.edit");
    await expect(asUser("2", () => a.transaction(async (c) =>
      a.expect(await c.query("DELETE FROM app.notes WHERE id = 1"), "app.notes", "delete", 1)))).rejects.toBeNotFound();
```

A database per worker, named after Jest's `JEST_WORKER_ID`:

```ts
    worker = await databasePerWorker(TESTS, { appUrl: appAt(TESTS) });
```

## Good to know

- The SDK's packages are ES modules: Jest runs them with `node --experimental-vm-modules`, as its own page on
  ES modules says.
- The matchers' types are for `expect` from `@jest/globals`.
- `asUser(who, fn)` is `actingAs` from `@rowstile/client`, under the name tests read best.
- The policy has tests of its own, in the policy's language (`rowstile test`): who sees what, who is
  refused. These matchers are for the app's code on top of it.

## More

- [Node apps](https://rowstile.dev/stacks/node): Express, node-postgres and Drizzle, with these tests, from an
  app the checks run.
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
| [`@rowstile/vitest`](https://www.npmjs.com/package/@rowstile/vitest) | Vitest: matchers, a database per worker |

rowstile is in beta: names may still change before 1.0. Apache-2.0.

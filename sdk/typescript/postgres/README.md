# @rowstile/postgres

[rowstile](https://rowstile.dev) is a policy language for PostgreSQL. You write who may see and change each
row in one file, and it becomes row-level security: the database filters every read and refuses every write
the rules don't allow, whatever the code asks.

This package is rowstile for postgres.js. `authz(sql)` gives `begin(fn)`, a transaction that signs in as
whoever the code acts for, the runtime's calls (`can`, `permsOf`, `list`, `share`), and `expect`, which turns
an UPDATE or DELETE that changed nothing into `NotFound` or `Refused` with the reason.

```sh
# @next on each: the newest pre-release (until 0.1.0 a plain install gets it too)
npm install @rowstile/client@next @rowstile/postgres@next
npm install --save-dev rowstile@next      # the command: rowstile dev, rowstile migrate
```

```ts
import { authz as postgresAuthz } from "@rowstile/postgres";

    const sql = postgres(APP, { max: 2 });
    const a = postgresAuthz(sql);
      const projects = await actingAs(["service", 1], () => a.begin(async (tx) => tx`SELECT id FROM app.projects ORDER BY id`));
```

A DELETE the rules refuse deletes 0 rows, without an error; `expect` asks the database why:

```ts
      await expect(a.begin(async (tx) => tx`DELETE FROM app.notes WHERE id = 1 RETURNING id`.then((rows) =>
        a.expect(rows, "app.notes", "delete", 1)), "2")).rejects.toBeNotFound();
```

## Good to know

- `begin(fn, who)` signs in as `who`, or as whoever `actingAs` set (`@rowstile/client`), else nobody.
- Every transaction signs in, even as nobody, and nothing uses a session-level `SET`: poolers in transaction
  mode are safe.
- `await a.check()` at start-up throws `ConnectionProblem` on a connection that skips row-level security.

## More

- [Node apps: pg, postgres.js and Drizzle](https://rowstile.dev/stacks/node): the whole setup, step by step, from an app the tests run.
- [The TypeScript SDK](https://rowstile.dev/sdk/typescript): every package, and the traps they handle.
- [Getting started](https://rowstile.dev/getting-started): a first policy, step by step.
- [Source and issues](https://github.com/rowstile/rowstile).

The other packages:

| package | for |
|---|---|
| [`@rowstile/client`](https://www.npmjs.com/package/@rowstile/client) | who a transaction acts for, the errors, the runtime's calls |
| [`@rowstile/prisma`](https://www.npmjs.com/package/@rowstile/prisma) | Prisma |
| [`@rowstile/pg`](https://www.npmjs.com/package/@rowstile/pg) | node-postgres |
| [`@rowstile/drizzle`](https://www.npmjs.com/package/@rowstile/drizzle) | Drizzle ORM |
| [`@rowstile/next`](https://www.npmjs.com/package/@rowstile/next) | Next.js: route handlers, server actions, caches |
| [`@rowstile/react`](https://www.npmjs.com/package/@rowstile/react) | React: hooks and a share dialog |
| [`@rowstile/vitest`](https://www.npmjs.com/package/@rowstile/vitest) | Vitest: matchers, a database per worker |

rowstile is in beta: names may still change before 1.0. Apache-2.0.

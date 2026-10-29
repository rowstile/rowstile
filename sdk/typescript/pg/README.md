# @rowstile/pg

[rowstile](https://rowstile.dev) is a policy language for PostgreSQL. You write who may see and change each
row in one file, and it becomes row-level security: the database filters every read and refuses every write
the rules don't allow, whatever the code asks.

This package is rowstile for node-postgres (`pg`). `authz(pool)` gives transactions that sign in as whoever
the code acts for, the runtime's calls (`can`, `permsOf`, `list`, `share`), and `expect`, which turns an UPDATE
or DELETE that changed nothing into `NotFound` or `Refused` with the reason. `changes(pool)` is the feed for
live updates.

```sh
# @next on each: the newest pre-release (until 0.1.0 a plain install gets it too)
npm install @rowstile/client@next @rowstile/pg@next
npm install --save-dev rowstile@next      # the command: rowstile dev, rowstile migrate
```

```ts
import { authz as rowstile } from "@rowstile/pg";

    const p = new pg.Pool({ connectionString: APP });
    const a = rowstile(p);
      expect(await a.transaction(async (c) => (await c.query("SELECT id FROM app.notes ORDER BY id")).rows.map((r) => r.id), "2")).toEqual([2, 3]);
```

`transaction(fn, who)` signs in as `who`, or as whoever `actingAs` set, else the `user` function, else nobody.
`fn` acts for them too: `expect`, `can` and the others called inside it run in its transaction. An UPDATE the
rules refuse changes 0 rows, without an error; `expect` asks the database why:

```ts
      await expect(actingAs("3", () => a.transaction(async (c) => {
        const r = await c.query("UPDATE app.notes SET body = 'x' WHERE id = 1");
        return a.expect(r, "app.notes", "update", 1);
      }))).rejects.toBeRefused("update");
```

## Good to know

- Every transaction signs in, even as nobody, and nothing uses a session-level `SET`: pools and poolers in
  transaction mode are safe.
- `await a.check()` at start-up throws `ConnectionProblem` on a connection that skips row-level security (a
  superuser, `BYPASSRLS`, the tables' owner).
- `changes(pool)` needs a connection of its own, straight to Postgres: `LISTEN` hears nothing through a
  pooler in transaction mode.
- Preview: Neon's serverless driver (`@neondatabase/serverless`) works too, over WebSockets, on Node.js and on an
  edge runtime. Its `Pool` goes where pg's does, and the transactions get Neon's own client. `pg` is an optional
  peer: an app on Neon's driver alone doesn't run it, and needs only `@types/pg`.

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
| [`@rowstile/postgres`](https://www.npmjs.com/package/@rowstile/postgres) | postgres.js |
| [`@rowstile/drizzle`](https://www.npmjs.com/package/@rowstile/drizzle) | Drizzle ORM |
| [`@rowstile/next`](https://www.npmjs.com/package/@rowstile/next) | Next.js: route handlers, server actions, caches |
| [`@rowstile/react`](https://www.npmjs.com/package/@rowstile/react) | React: hooks and a share dialog |
| [`@rowstile/vitest`](https://www.npmjs.com/package/@rowstile/vitest) | Vitest: matchers, a database per worker |
| [`@rowstile/jest`](https://www.npmjs.com/package/@rowstile/jest) | Jest (preview): matchers, a database per worker |

rowstile is in beta: names may still change before 1.0. Apache-2.0.

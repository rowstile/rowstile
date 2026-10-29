# @rowstile/client

[rowstile](https://rowstile.dev) is a policy language for PostgreSQL. You write who may see and change each
row in one file, and it becomes row-level security: the database filters every read and refuses every write
the rules don't allow, whatever the code asks.

This package is the base of the TypeScript SDK: who a transaction acts for, the errors a refusal becomes, and
the runtime's calls (`can`, `perms`, `list`, `share`, ...). The driver packages build on it: `@rowstile/prisma`,
`@rowstile/pg`, `@rowstile/postgres`, `@rowstile/drizzle`. It holds no rowstile logic: it calls the `authz.*`
functions the policy made, and translates their answers.

```sh
# @next: the newest pre-release (until 0.1.0 a plain install gets it too)
npm install @rowstile/client@next
npm install --save-dev rowstile@next      # the command: rowstile dev, rowstile migrate
```

A background job that acts for a service, whatever started it:

```ts
// src/jobs.ts
import { current, job } from "@rowstile/client";
import { db } from "./db.ts";

export const digest = job(["service", 1], async () => ({ count: await db.project.count(), who: current() }));
```

## What is in it

- `actingAs(who, fn)` and `job(who, fn)`: every transaction `fn` begins signs in as `who`. `42` or `"42"` is
  a user, `["service", 3]` another principal type of the policy, `null` nobody.
- `current()`: who the code running now acts for.
- `Refused` (403, with the rule and the reason), `NotFound` (404), `NotSignedIn`, `ConnectionProblem`.
- `translate(e)`: any driver's error as one of those, or `null`. `problemOf(e)` and `problemResponse(e)`: the
  status and an RFC 9457 body for an HTTP answer (and 404 for what a call names that isn't there, AZ708; 400
  for a missing or wrong argument, AZ710; 401 for a call that needs someone signed in or a login refused,
  AZ714 and AZ703; 409 for a move inside itself, AZ713).
- `errorCode(e)`: rowstile's code for an error (`AZ709`; `rowstile help AZ709` explains it).
- `notSignedIn(e)`: whether an error is the not-signed-in one (AZ701: a query in a transaction nobody signed
  in to). A login refused (AZ703) and settings changed by hand (AZ702) have its SQLSTATE, 28000, but are not it.
- `calls(queryable)`: the runtime's functions over anything with `query(text, values)`; with them
  `tableName(table)`, the table as the policy names it, with its schema (`public.Note` for `Note`), as a
  refusal's `table` names it.
- `Register`: the interface the generated names fill in (`rowstile client`), so a wrong permission name
  doesn't type-check.

## More

- [Node apps: pg, postgres.js and Drizzle](https://rowstile.dev/stacks/node): the whole setup, step by step, from an app the tests run.
- [The TypeScript SDK](https://rowstile.dev/sdk/typescript): every package, and the traps they handle.
- [Getting started](https://rowstile.dev/getting-started): a first policy, step by step.
- [Source and issues](https://github.com/rowstile/rowstile).

The other packages:

| package | for |
|---|---|
| [`@rowstile/prisma`](https://www.npmjs.com/package/@rowstile/prisma) | Prisma |
| [`@rowstile/pg`](https://www.npmjs.com/package/@rowstile/pg) | node-postgres |
| [`@rowstile/postgres`](https://www.npmjs.com/package/@rowstile/postgres) | postgres.js |
| [`@rowstile/drizzle`](https://www.npmjs.com/package/@rowstile/drizzle) | Drizzle ORM |
| [`@rowstile/next`](https://www.npmjs.com/package/@rowstile/next) | Next.js: route handlers, server actions, caches |
| [`@rowstile/react`](https://www.npmjs.com/package/@rowstile/react) | React: hooks and a share dialog |
| [`@rowstile/vitest`](https://www.npmjs.com/package/@rowstile/vitest) | Vitest: matchers, a database per worker |
| [`@rowstile/jest`](https://www.npmjs.com/package/@rowstile/jest) | Jest (preview): matchers, a database per worker |

rowstile is in beta: names may still change before 1.0. Apache-2.0.

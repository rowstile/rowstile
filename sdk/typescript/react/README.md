# @rowstile/react

[rowstile](https://rowstile.dev) is a policy language for PostgreSQL. You write who may see and change each
row in one file, and it becomes row-level security: the database filters every read and refuses every write
the rules don't allow, whatever the code asks.

This package is the React kit: what the signed-in user may do, for buttons and menus. The database still
decides; these only ask it, so the page doesn't offer what would be refused. `usePerms` asks for a whole list
in one call, `<Can>` shows or hides, `<ShareDialog>` is a headless share dialog, `useAccessRequest` asks for
access, and all of them stay current over server-sent events.

```sh
# @next on each: the newest pre-release (until 0.1.0 a plain install gets it too)
npm install @rowstile/react@next @rowstile/next@next
```

```tsx
import { AuthzProvider, Can, ShareDialog, useAccessRequest, usePerms } from "@rowstile/react";

function Buttons() {
  const perms = usePerms("project", [1, 2, 3]);
  if (perms.loading) return <p>loading</p>;
  return <ul>{[1, 2, 3].map((id) => <li key={id}>{id}:{perms(id).perms.join(",")}{perms(id).can("edit") && " [rename]"}</li>)}</ul>;
}
```

```tsx
      <Can type="project" id={1} perm="edit" fallback={<span>no edit on 1</span>}><span>edit on 1</span></Can>
```

The server's side is one file, with `@rowstile/next`:

```ts
// app/api/authz/[...authz]/route.ts
import { authzRoutes } from "@rowstile/next";
import { db, feed } from "@/db";

export const { GET, POST } = authzRoutes({ calls: db.$authz, changes: feed });
```

## Good to know

- Wrap the app in `<AuthzProvider>`: with Next.js's App Router, in `app/layout.tsx`. The kit is a client
  module (`"use client"`), so a server component renders it as it is, with no wrapper of your own.
- Give `<AuthzProvider>` `user={id}` if the user can change without a page load: the hooks forget what they had
  and ask again.
- The answers are for the page only. A user who edits the page still meets the database, which refuses.
- React 19, from 19.3.

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
| [`@rowstile/vitest`](https://www.npmjs.com/package/@rowstile/vitest) | Vitest: matchers, a database per worker |
| [`@rowstile/jest`](https://www.npmjs.com/package/@rowstile/jest) | Jest (preview): matchers, a database per worker |

rowstile is in beta: names may still change before 1.0. Apache-2.0.

# rowstile for TypeScript

The SDK for TypeScript apps on a rowstile policy: every transaction signs in as whoever the request
or the job acts for, refused writes become a 403 with the database's reason, rows the user can't see a 404,
signed-in reads stay out of Next.js's caches, and the app refuses to start on a connection that skips
row-level security. It holds no rowstile logic: it calls the `authz.*` functions the policy made, and
translates their answers.

Next.js with Prisma:

```ts
// src/db.ts
import { PrismaPg } from "@prisma/adapter-pg";
import { authz, signedIn } from "@rowstile/prisma";
import "@rowstile/next";                         // signed-in reads never land in a cache
import "./authz.gen";                            // the policy's names (rowstile client)

// the app's own URL, as the role the policy names: never the owner's, which Prisma migrates with
const adapter = signedIn(new PrismaPg({ connectionString: process.env.ROWSTILE_APP_URL }),
                         { user: async () => (await auth())?.user.id });
export const db = new PrismaClient({ adapter }).$extends(authz());
```

```ts
// app/api/folders/[id]/route.ts: no checks; a hidden folder is 404, one the user may not rename 403
export const PATCH = route(async (req: Request, { params }: { params: Promise<{ id: string }> }) => {
  await db.folder.update({ where: { id: Number((await params).id) }, data: await req.json() });
  return Response.json({ ok: true });
});
```

| package | what |
|---|---|
| `@rowstile/client` | `actingAs(who, fn)`, `job(who, fn)`, `current()`, `Refused`, `NotFound`, `NotSignedIn`, `translate(e)`, `problemOf(e)` and `problemResponse(e)` for any driver's error (a problem's fields: `status`, `type`, `title`, `detail`, and a refusal's `table`, `command`, `why` and `code`), `errorCode(e)` (rowstile's code: `AZ709`), `notSignedIn(e)` (whether it is the not-signed-in error, AZ701; a login refused, AZ703, and settings changed by hand, AZ702, have its SQLSTATE but are not it), `calls(queryable)` (the runtime's functions), the `Register` the generated names fill in |
| `@rowstile/prisma` | `signedIn(adapter, { user })`: every transaction Prisma begins signs in; `authz()`: P2025 as `NotFound` or `Refused` with the reason, refused creates naming the rule, `db.$authz` (`can`, `ids`, `permsOf`, `share`, `check`, ...; `tableName("Note")`: the table as the policy names it, `public.Note`, as a refusal's `table` names it) |
| `@rowstile/pg` | `authz(pool, { user })`: `transaction(fn)`, `query()`, the runtime's functions; `changes(pool)` for live updates |
| `@rowstile/postgres` | `authz(sql, { user })`: `begin(fn)`, the runtime's functions |
| `@rowstile/drizzle` | `withAuthz(db, { user })`: `transaction(fn)`; `inIds(column, type, perm)` and `ids()` for `where`; `expect(tx, result, ...)` for updates and deletes that changed nothing |
| `@rowstile/next` | `route(handler)` (403 and 404 problem bodies), `action(fn)` (`{ ok, value }` or `{ ok: false, problem }`), `authzRoutes()` (what the React kit calls), `checkAtStart()` for `instrumentation.ts`; importing it keeps signed-in reads out of caches |
| `@rowstile/react` | `<AuthzProvider>`, `usePerms(type, ids)` (one call for a list), `<Can>`, `useShares` and a headless `<ShareDialog>`, `useAccessRequest`; kept current over server-sent events |
| `@rowstile/vitest` | `expect.extend(matchers)`: `toBeRefused(command, reason)`, `toBeNotFound()`; `asUser(who, fn)`; `databasePerWorker(url)`. Vitest 4 or 5 |

They run on Node 22.12 or newer, with Next.js 16, React 19, Prisma 7, node-postgres 8, postgres.js 3, Drizzle
0.45 and Vitest 4 or 5. Each package's `peerDependencies` names the majors the checks run, from the version they
ran (`"next": "^16.4.0"`), so npm refuses another unless told to.

Who a transaction acts for: `42` or `"42"` (a user), `["service", 3]` (another principal type of the policy),
or `null` (nobody: only what `anyone` may see). A plain id is always a user's, whatever it holds: `"service:3"`
is the user with that id, so an id from outside (a username, an identity provider's subject) can't name a
service. `parsePrincipal(text)` reads back what `describe()` wrote, for text your own code wrote (a job's
argument): `describe()` writes a user whose id holds `:` or is `nobody` as `user:<id>` (`user:service:3`), so
every principal reads back as itself. The audit trail and `created_by` name who acted the same way, so
`parsePrincipal` reads them too. Whoever the code acts for (`actingAs`, a `job`)
comes first, else the `user` function, else nobody; a `who` given to one call (`transaction(fn, who)`) comes
before all, and `null` there is nobody. The code in `fn` acts for that transaction's principal too: the
package's own calls made there (`a.expect`, `a.can`) run in the same transaction. Every transaction signs in, even as nobody, and nothing uses a
session-level `SET`, so pools and poolers in transaction mode are safe; the change feed needs its own connection
to Postgres ([Behind a pooler](../../docs/operations.md#behind-a-pooler)).

Traps it handles:

- **Next.js caching.** Before a transaction signs in as someone, `@rowstile/next` calls Next's `connection()`:
  the render is dynamic, and a signed-in read inside `"use cache"` or `unstable_cache` fails instead of being
  cached for the next user. Reads as nobody may be cached.
- **Prisma answers some calls together.** It dispatches the `findUnique` calls of one tick, and array
  transactions, from the first caller's context. `authz()` runs each `findUnique` in a transaction of its own,
  and refuses `$transaction([...])` (use `$transaction(async (tx) => ...)`), so no query runs as someone else.
  Use the client `$extends(authz())` returns, and only that one: the client it was made from is refused
  whenever it is used, inside your own extensions too. An extension you add to the client `authz()` returns is
  placed before it, so `authz()` stays the last one: each of your query hooks runs once for a call, and sees
  the errors `authz()` makes (`Refused`, `NotFound`).
- **Inserts that read the row back** (`RETURNING`, Prisma's `create`) also need the select rule, and so do
  updates after which the user could no longer see the row: Postgres's own message comes back as `Refused`
  naming the select rule. An upsert of a row the user may not change names the update rule, and a MERGE's
  refusal names no command (Postgres doesn't say whether the update or the delete rule).
- **Prisma's promises are lazy**: `actingAs` and `job` await what they return inside their scope.
- **A connection that drops.** node-postgres stops the process when a client that is checked out loses its
  connection and nobody listens: `@rowstile/pg`, and `@rowstile/drizzle` on node-postgres, listen while a
  transaction holds one, so the transaction fails instead.
  `changes(pool)` listens again after its connection drops, and tells its subscribers once.
- **An update that changed nothing** is `NotFound` when the user can't see the row, `Refused` when the database
  says no, and `NotFound` again when the rule allows it and the statement matched nothing for another reason
  (a `where` with more than the key).
- **The answers in the browser are one user's.** Give `<AuthzProvider user={id}>` if the user can change
  without a page load: the hooks forget what they had and ask again.

The types and permissions of the policy are generated names: with a `@rowstile/*` dependency in
`package.json`, `rowstile client` writes only the names (`[clients] ts = "src/authz.gen.ts"`), registered with
the SDK, so `db.$authz.can("note", 1, "edt")` doesn't type-check. Policy changes ship as migrations for your
tool (`rowstile migrate`, with `tool = "prisma"` or `"drizzle"` in `rowstile.toml`).

The packages are an npm workspace at the repository root (`npm ci`, then `npx tsc -b sdk/typescript`).
`integrations/nextjs/` is the conformance suite: a small Next.js app on Prisma 7 and Prisma Migrate, and the
checks every supported stack passes, with pg, postgres.js, Drizzle and the React kit
(`integrations/nextjs/test.sh`).

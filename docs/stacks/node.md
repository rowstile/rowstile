# Node apps: pg, postgres.js and Drizzle

<!-- tested: every line of code below is in integrations/nextjs or integrations/node (tests/unit_test.py checks it) -->

Any Node app (Express, Fastify, Hono, a worker) on `pg`, postgres.js or Drizzle. Each transaction signs in as
whoever the code acts for, the database filters what it reads and refuses what it may not write, and the
SDK turns a refusal into `Refused` (403) and a hidden row into `NotFound` (404). Next.js with Prisma:
[Next.js](nextjs.md), which also covers the React kit, and Next.js with pg in a section of its own.

These come from two conformance suites: the Next.js app's checks without Prisma
([`integrations/nextjs/tests/conformance.test.ts`](../../integrations/nextjs/tests/conformance.test.ts)), and a plain Express server's ([`integrations/node`](../../integrations/node)), whose tests
run on Jest. The Express app and `@rowstile/jest` are a **preview**: they may change in any release, and are not
part of what 1.0 will freeze.

## Who a transaction acts for

`actingAs(who, fn)` signs in every transaction `fn` begins: `"42"` (a user), `["service", 1]` (another principal
type of the policy), or `null` (nobody: only what `anyone` may see). In a web app, call it in a middleware
around each request. A background job is `job(who, fn)`. Every transaction signs in, even as nobody, and nothing
uses a session-level `SET`, so pools and poolers in transaction mode are safe. The change feed (`changes()`)
needs its own connection to Postgres: [Behind a pooler](../operations.md#behind-a-pooler).

A transaction is one principal's: a sign-in lasts the database transaction. Inside `transaction(fn)`, the same
object's work for anyone else (code in `fn` that calls `actingAs` or a job, a `who` given, or nobody) throws an
`Error` before anything is sent for it, and the transaction goes on as its own principal. Run that work after it,
or in a transaction of its own on another connection.

```sh
# @next on each: the newest pre-release (until 0.1.0 a plain install gets it too)
npm install @rowstile/client@next @rowstile/pg@next   # or @rowstile/postgres@next, @rowstile/drizzle@next
npm install --save-dev rowstile@next                  # the command
npm install --save-dev @rowstile/jest@next            # tests on Jest (a preview)
```

## Express

*A preview.* One middleware makes each request act for its user, and every transaction the routes begin signs
in as them. `userOf(req)` is your session's user: your own cookie or token, or Passport's `req.user`.

```ts
export const app = express();
app.use(express.json());
// every transaction a request begins signs in as its user (none: nobody, who sees only what `anyone` may)
app.use((req, _res, next) => actingAs(userOf(req), next));
```

The database, on one pool: node-postgres and Drizzle, each transaction signed in.

```ts
export const pool = new pg.Pool({ connectionString: url, max: Number(process.env.PG_POOL_MAX ?? 5) });
export const sql = authz(pool);                       // sql.transaction(fn), sql.query(), sql.can(), ...
export const db = withAuthz(drizzle(pool));           // db.transaction((tx) => tx.select()...)
```

The routes check nothing themselves. A refused write throws, and so does an update that changed no row
(`drizzleExpect` asks the database why):

```ts
// an update the rules may refuse: a hidden note is 404, one the user may not edit 403 with the reason
app.patch("/api/notes/:id", async (req, res) => {
  const { body } = req.body as { body: string };
  await db.transaction(async (tx) => drizzleExpect(tx,
    await tx.update(notes).set({ body }).where(eq(notes.id, id(req))).returning({ id: notes.id }), "app.notes", "update", id(req)));
  res.json({ id: id(req) });
});
```

The error handler, last, answers with the problem: 403 with the rule and the reason, 404, and the database's
other answers as their codes' pages say. Anything else is the app's mistake: it goes on to Express's own
handler, a 500.

```ts
export function problems(err: unknown, _req: Request, res: Response, next: NextFunction): void {
  const problem = problemOf(err);
  if (problem) res.status(problem.status).type("application/problem+json").json(problem);
  else next(err);
}

app.use(problems);
```

At start-up, before it listens, the server refuses a connection that skips row-level security:

```ts
await sql.check();
```

A background job acts for its service, whatever started it:

```ts
export const digest = job(["service", 1], async () => ({
  count: (await sql.query<{ n: number }>("SELECT count(*)::int AS n FROM app.projects")).rows[0]?.n,
  who: current(),
}));
```

## pg

```ts
import { authz as rowstile } from "@rowstile/pg";

    const p = new pg.Pool({ connectionString: APP });
    const a = rowstile(p);
      expect(await a.transaction(async (c) => (await c.query("SELECT id FROM app.notes ORDER BY id")).rows.map((r) => r.id), "2")).toEqual([2, 3]);
```

`transaction(fn, who)` signs in as `who`, or as whoever `actingAs` set, else the `user` function, else nobody.
`fn` acts for them too: `expect`, `can` and the others called inside it run in its transaction, as `who`, and
see what it wrote. An UPDATE or DELETE the rules refuse changes 0 rows, without an error; `expect` asks the
database why, and throws `Refused` with the rule and the reason, or `NotFound`:

```ts
      await expect(actingAs("3", () => a.transaction(async (c) => {
        const r = await c.query("UPDATE app.notes SET body = 'x' WHERE id = 1");
        return a.expect(r, "app.notes", "update", 1);
      }))).rejects.toBeRefused("update");
```

A refused INSERT is an error already, and `query()` (a transaction of one statement) throws it as `Refused`,
naming the rule's permission:

```ts
      await expect(actingAs("2", () => a.query("INSERT INTO app.notes (project_id, author_id, body) VALUES (3, 2, 'hi')")))
        .rejects.toBeRefused("insert", "project.edit");
      expect(await actingAs("3", () => a.can("project", 1, "edit"))).toBe(true);
```

At start-up, `await a.check()` throws `ConnectionProblem` on a connection that skips row-level security (a
superuser, BYPASSRLS, the tables' owner).

## postgres.js

```ts
import { authz as postgresAuthz } from "@rowstile/postgres";

    const sql = postgres(APP, { max: 2 });
    const a = postgresAuthz(sql);
      const projects = await actingAs(["service", 1], () => a.begin(async (tx) => tx`SELECT id FROM app.projects ORDER BY id`));
      expect(await a.permsOf("project", [1, 3])).toEqual({ "1": [], "3": ["view"] });   // signed out
```

## Drizzle

`withAuthz(db)` gives Drizzle's transactions a sign-in; `inIds(column, type, perm)` filters a query to the
objects the user holds a permission on.

```ts
import { expect as drizzleExpect, inIds, withAuthz } from "@rowstile/drizzle";

    const d = drizzle(p);
    const a = withAuthz(d);
      const editable = await a.transaction((tx) => tx.select({ id: projects.id }).from(projects).where(inIds(projects.id, "project", "edit")), "3");
      await expect(a.transaction(async (tx) => drizzleExpect(tx, await tx.delete(notes).where(eq(notes.id, 1)).returning(),
        "app.notes", "delete", 1), "3")).rejects.toBeRefused("delete");
```

A query outside a signed-in transaction fails with the not-signed-in error (AZ701); `translate(e)` makes it
`NotSignedIn`:

```ts
      const e = await d.select().from(notes).catch((err) => err);  // outside a signed-in transaction
      expect(translate(e)).toBeInstanceOf(NotSignedIn);
```

`notSignedIn(e)` (in `@rowstile/client`) says whether an error is that one. A login the database refuses
(AZ703) and settings changed by hand (AZ702) have its SQLSTATE, 28000, but are not it.

## The Neon serverless driver (preview)

*Preview: this part may change in any release, and is not part of the 1.0 freeze.*

Neon's serverless driver, `@neondatabase/serverless`, talks to Postgres over WebSockets. Its `Pool` works as pg's
does, and `@rowstile/pg` takes it as it takes pg's: the transactions get Neon's own client, typed.

```ts
import { Pool, neonConfig } from "@neondatabase/serverless";
import { authz } from "@rowstile/pg";

  const one = new Pool({ connectionString: NEON, max: 1 });
  const a = authz(one);
      const ids = await a.transaction(async (c) => (await c.query("SELECT id FROM app.notes ORDER BY id")).rows.map((r) => r.id), user || null);
```

On Neon it needs no settings. In front of your own Postgres it needs a WebSocket proxy, Neon's `wsproxy`, and
`neonConfig.wsProxy`, `useSecureWebSocket = false` and `pipelineConnect = false`
([Next.js](nextjs.md#the-neon-serverless-driver-and-the-edge-runtime-preview) shows them). On an edge runtime, a
pool can't outlive the request that opened it: make one in each request, and end it once the response is sent.
`pg` is an optional peer of `@rowstile/pg`: an app on Neon's driver alone doesn't run it, and needs only its
types (`npm install --save-dev @types/pg`), which `@rowstile/pg`'s own name.

## Background jobs: BullMQ (preview)

*Preview: this part may change in any release, and is not part of the 1.0 freeze.*

`job(who, fn)` gives a queue worker its processor: each job signs in as `who`, whoever queued it, and the worker's
own code outside the job acts for nobody.

```ts
import { Queue, Worker } from "bullmq";

const connection = { url: process.env.REDIS_URL, maxRetriesPerRequest: null };
export const digestWorker = () => new Worker("digest", digest, { connection });
```

`digest` is `job(["service", 1], async () => ...)` ([Next.js](nextjs.md#background-jobs)). Start the worker at the
top level of its process.

## Answering HTTP

In your framework's error handler, `problemOf(e)` (in `@rowstile/client`) gives the status and the problem body
for any driver's error that is a refusal (403, with the rule and the reason) or a hidden row (404), a call the
database says names something that isn't there (404, AZ708) or lacks an argument or has a wrong one (400,
AZ710), a call that needs someone signed in or a login refused (401, AZ714 and AZ703), a move inside itself
(409, AZ713), and `null` for anything else. A problem's fields are its own, not under a `body`: `status`, `type`, `title` and `detail` (the database's words), and a refusal's `table`, `command`, `why` (the reason, a line each) and `code`. `problemResponse(e)` is the same as a Fetch `Response`, for Hono and other frameworks built
on it.

## Tests on Jest

*A preview.* `@rowstile/jest` is `@rowstile/vitest` for Jest 30: the same matchers, `asUser`, and a copy of
the migrated test database for each Jest worker. The SDK's packages are ES modules, so Jest runs them with
`node --experimental-vm-modules`.

```ts
// tests/setup.ts
import { expect } from "@jest/globals";
import { matchers } from "@rowstile/jest";

expect.extend(matchers);
```

```ts
    worker = await databasePerWorker(TESTS, { appUrl: appAt(TESTS) });
    await expect(asUser("2", () => a.query("INSERT INTO app.notes (project_id, author_id, body) VALUES (3, 2, 'hi')")))
      .rejects.toBeRefused("insert", "project.edit");
```

## Migrations

Policy changes ship as migrations for your tool: `tool = "drizzle"` (Drizzle Kit's journal), `"sql"`,
`"goose"`, `"dbmate"` or `"flyway"` in `rowstile.toml`. `npx rowstile migrate` writes the next one;
`npx rowstile migrate --check` in CI fails if a policy change has none.

With Drizzle Kit, `drizzle-kit migrate` runs rowstile's migrations with yours, and `drizzle-kit generate` finds
nothing to change after them: each copies the snapshot before it. Never `drizzle-kit push` a database the
policy governs. Drizzle Kit models row-level security, and your schema declares none of rowstile's, so push
would turn it off and drop every rule.

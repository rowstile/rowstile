# Node apps: pg, postgres.js and Drizzle

<!-- tested: every line of code below is in integrations/nextjs (tests/unit_test.py checks it) -->

Any Node app (Express, Fastify, Hono, a worker) on `pg`, postgres.js or Drizzle. Each transaction signs in as
whoever the code acts for, the database filters what it reads and refuses what it may not write, and the
SDK turns a refusal into `Refused` (403) and a hidden row into `NotFound` (404). Next.js with Prisma:
[Next.js](nextjs.md), which also covers the React kit, and Next.js with pg in a section of its own.

These come from the conformance suite's checks without Prisma (`integrations/nextjs/tests/conformance.test.ts`).

## Who a transaction acts for

`actingAs(who, fn)` signs in every transaction `fn` begins: `"42"` (a user), `["service", 1]` (another principal
type of the policy), or `null` (nobody: only what `anyone` may see). In a web app, call it in a middleware
around each request. A background job is `job(who, fn)`. Every transaction signs in, even as nobody, and nothing
uses a session-level `SET`, so pools and poolers in transaction mode are safe. The change feed (`changes()`)
needs its own connection to Postgres: [Behind a pooler](../operations.md#behind-a-pooler).

```sh
# @next on each: the newest pre-release (until 0.1.0 a plain install gets it too)
npm install @rowstile/client@next @rowstile/pg@next   # or @rowstile/postgres@next, @rowstile/drizzle@next
npm install --save-dev rowstile@next                  # the command
```

## pg

```ts
import { authz as rowstile } from "@rowstile/pg";

    const p = new pg.Pool({ connectionString: APP });
    const a = rowstile(p);
      expect(await a.transaction(async (c) => (await c.query("SELECT id FROM app.notes ORDER BY id")).rows.map((r) => r.id), "2")).toEqual([2, 3]);
```

`transaction(fn, who)` signs in as `who`, or as whoever `actingAs` set. An UPDATE or DELETE the rules refuse
changes 0 rows, without an error; `expect` asks the database why, and throws `Refused` with the rule and the
reason, or `NotFound`:

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

A query outside a signed-in transaction fails with strict sign-in's error; `translate(e)` makes it
`NotSignedIn`:

```ts
      const e = await d.select().from(notes).catch((err) => err);  // outside a signed-in transaction
      expect(translate(e)).toBeInstanceOf(NotSignedIn);
```

## Answering HTTP

In your framework's error handler, `problemOf(e)` (in `@rowstile/client`) gives the status and the problem body
for any driver's error that is a refusal (403, with the rule and the reason) or a hidden row (404), a call the
database says names something that isn't there (404, AZ708) or lacks an argument or has a wrong one (400,
AZ710), a call that needs someone signed in or a login refused (401, AZ714 and AZ703), a move inside itself
(409, AZ713), and `null` for anything else. A problem's fields are its own, not under a `body`: `status`, `type`, `title` and `detail` (the database's words), and a refusal's `table`, `command`, `why` (the reason, a line each) and `code`. `problemResponse(e)` is the same as a Fetch `Response`, for Hono and other frameworks built
on it.

## Migrations

Policy changes ship as migrations for your tool: `tool = "drizzle"` (Drizzle Kit's journal), `"sql"`,
`"goose"`, `"dbmate"` or `"flyway"` in `rowstile.toml`. `npx rowstile migrate` writes the next one;
`npx rowstile migrate --check` in CI fails if a policy change has none.

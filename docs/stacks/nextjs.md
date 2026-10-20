# Next.js and Prisma

<!-- tested: every line of code below is in integrations/nextjs (tests/unit_test.py checks it) -->

A Next.js app (App Router) on Prisma 7, whose migrations are Prisma Migrate's. Route handlers, server actions and
pages check nothing: each transaction signs in as the request's user, the database filters what it reads and
refuses what it may not write, and the SDK answers a refusal with 403 and a hidden row with 404. Signed-in
reads never land in a cache another user could be served from.

Everything here comes from `integrations/nextjs`, the conformance suite: a small app and the checks every
supported stack passes (`integrations/nextjs/test.sh`, against the production build). Drizzle, pg and
postgres.js: [Node apps](node.md).

To start from an app that runs instead of from this page: the
[Next.js and Prisma starter](https://github.com/rowstile/starter-nextjs-prisma), a template repository.
`docker compose up`, and documents are shared with people and teams, with the policy, its tests and the review
in CI already there.

## Install

```sh
# Prisma 7 and its Postgres adapter, if the app doesn't have them yet
npm install @prisma/client@7 @prisma/adapter-pg@7 pg && npm install --save-dev prisma@7
# @next on each while only an alpha is published: a plain install gets an older one
npm install @rowstile/client@next @rowstile/prisma@next @rowstile/next@next @rowstile/react@next
npm install --save-dev rowstile@next @rowstile/vitest@next
npx rowstile init        # a first policy from your tables, a test file, rowstile.toml
```

The `rowstile` package is the command, with its own Python: nothing else to install. `init` reads your
tables, so it needs the database, as their owner: `DATABASE_URL`, or `--db`. The command reads its
variables from the environment, then from `.env.local` and `.env` in the project's folder, where Next.js
and Prisma keep theirs. It finds Next.js and Prisma, and writes `rowstile.toml` for them. The conformance app's, with its own name for the variable that
holds the owner's connection:

```toml
policy   = "db/policy.authz"
tests    = ["db/tests/*.authz"]
database = "env:ROWSTILE_OWNER_DSN"
[clients]
ts = "src/authz.gen.ts"
[migrations]
tool = "prisma"
dir  = "prisma/migrations"
```

Two roles connect. The owner of the tables runs the migrations (`ROWSTILE_OWNER_DSN`), and the app connects
as the role the policy names, which row-level security applies to (`ROWSTILE_APP_URL`). Prisma migrates, so
its own configuration takes the owner's URL:

```ts
// prisma.config.ts
import { defineConfig, env } from "prisma/config";

export default defineConfig({
  schema: "prisma/schema.prisma",
  migrations: { path: "prisma/migrations" },
  datasource: { url: env("ROWSTILE_OWNER_DSN") },
});
```

The app role and what it may do are a migration like the others, written by hand. A role belongs to the
whole server, and Prisma's shadow database runs every migration again: the role is made only where it is
missing. Grant it what the app does: reading, and writing the tables the app writes.

```sql
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'conf_app') THEN
    CREATE ROLE conf_app LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'app';
  END IF;
END $$;
GRANT USAGE ON SCHEMA "app" TO conf_app;
GRANT SELECT ON ALL TABLES IN SCHEMA "app" TO conf_app;
GRANT INSERT, UPDATE, DELETE ON "app"."notes", "app"."inbox" TO conf_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA "app" TO conf_app;
```

With Prisma's default schema, `public`, name the tables in the first grant: `ALL TABLES` there includes
Prisma's own `_prisma_migrations`. The owner must also be able to switch to the app role, since the command
looks at the data as the app does when it runs the policy's tests: an owner that isn't a superuser gives
itself the role once, `GRANT conf_app TO conf_owner` (the command says so when it is missing, AZ618).

## The database client

`signedIn` wraps Prisma's driver adapter: every transaction Prisma begins signs in as whoever `user` returns
for the request (`null`: nobody, who sees only what `anyone` may). `authz()` turns Prisma's "record not found"
into 404 or 403 with the reason, and adds `db.$authz`. Use the client `$extends(authz())` returns, and only
that one: the client it was made from is refused whenever it is used, inside your own Prisma extensions too
(add them to the client `authz()` returns: they are placed before it, and each hook runs once for a call).
Importing `@rowstile/next` keeps signed-in reads out of Next.js's caches, and `authz.gen.ts` (written by
`rowstile client`) gives the SDK the policy's names, so a misspelled permission doesn't type-check.
The imports below end in `.ts` and the app's own start with `@/`: `allowImportingTsExtensions`, and
`"paths": { "@/*": ["./src/*"] }`, in `tsconfig.json`.

```ts
import { PrismaPg } from "@prisma/adapter-pg";
import { headers } from "next/headers";
import pg from "pg";
import { authz, signedIn } from "@rowstile/prisma";
import "@rowstile/next";                              // signed-in reads never land in a cache
import { PrismaClient } from "./generated/prisma/client.ts";
import "./authz.gen.ts";                              // the policy's names, for the SDK's types

/** Who the request is. A real app reads its session (auth()); the conformance app, a header. */
export async function requestUser(): Promise<string | null> {
  return (await headers()).get("x-user");
}

const url = process.env.ROWSTILE_APP_URL;
export const pool = new pg.Pool({ connectionString: url, max: Number(process.env.PG_POOL_MAX ?? 5) });
export const db = new PrismaClient({ adapter: signedIn(new PrismaPg(pool), { user: requestUser }) }).$extends(authz());
```

At start-up, the server stops if its connection skips row-level security (a superuser, BYPASSRLS, the tables'
owner), where the database would filter nothing:

```ts
// instrumentation.ts
import { checkAtStart } from "@rowstile/next";

export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") await checkAtStart((await import("./src/db.ts")).db.$authz);
}
```

Next.js looks for that file beside `app/`: in an app made with `--src-dir`, where `app/` is inside `src/`, it
is `src/instrumentation.ts`, and it imports `./db.ts`.

## Pages, route handlers and server actions

A page reads as the request's user:

```tsx
export default async function Notes() {
  const notes = await db.note.findMany({ select: { id: true, body: true }, orderBy: { id: "asc" } });
```

`route()` answers a refusal with a problem body: 404 for a row the user can't see, 403 with the rule and the
reason for one they may not change (its fields: <https://rowstile.dev/problems/refused>). A call the database
says names something that isn't there (a share with someone who doesn't exist) is 404 too, one it says
lacks an argument or has a wrong one (a negative page size) 400, one that needs someone signed in, from a
visitor who isn't, 401, and a folder moved into one of its own subfolders 409, each with the database's words.
Prisma's driver adapter keeps no hint for SQLSTATE 28000, so a login the database refuses
(`authz.login_key`, AZ703) reads as `NotSignedIn` through Prisma; through `pg` it answers 401.

```ts
import { route } from "@rowstile/next";
import { db } from "@/db";

type Params = { params: Promise<{ id: string }> };

// an update the rules may refuse: a hidden note is 404, one the user may not edit 403 with the reason
export const PATCH = route(async (req: Request, { params }: Params) => {
  const id = Number((await params).id);
  const { body } = (await req.json()) as { body: string };
  await db.note.update({ where: { id }, data: { body } });
  return Response.json({ id });
});
```

Next.js hides a server action's thrown error from the browser, so `action()` returns the problem instead,
`{ ok: false, problem }`:

```ts
"use server";
import { action } from "@rowstile/next";

export const renameNote = action(async (id: number, body: string) => {
  await db.note.update({ where: { id }, data: { body } });
  return id;
});
```

Prisma's `create` reads the new row back, so an insert also needs the select rule; if the user may insert but
not read the row, the 403 names the select rule.

Two Prisma habits are handled: each `findUnique` runs in a transaction of its own (Prisma answers the calls of
one tick together, from the first caller's context), and array transactions, `$transaction([...])`, are
refused for the same reason. Use `$transaction(async (tx) => ...)`; inside it, why a write was refused is asked
through the transaction, so it needs no second connection. Those transactions wait for a connection
as long as Prisma's `transactionOptions` say, 2 seconds by default: with the database far away and many
`findUnique` calls at once, give the client a longer `maxWait` (or a bigger pool), or they fail with
"Unable to start a transaction in the given time".

## Buttons, sharing and live updates (React)

`authzRoutes()` is what the React kit calls: permissions for a list, shares, access requests, and live updates
from the change feed.

```ts
// app/api/authz/[...authz]/route.ts
import { authzRoutes } from "@rowstile/next";
import { db, feed } from "@/db";

export const { GET, POST } = authzRoutes({ calls: db.$authz, changes: feed });
```

```ts
import { changes } from "@rowstile/pg";

// live updates for @rowstile/react: one connection that LISTENs, beside the pool, straight to Postgres
// (through a pooler in transaction mode LISTEN hears nothing: ROWSTILE_FEED_URL is the direct URL then)
export const feed = changes(new pg.Pool({ connectionString: process.env.ROWSTILE_FEED_URL ?? url, max: 1 }));
```

`usePerms` answers a list's buttons in one call, and `<Can>` shows what the user may do:

```tsx
function Buttons() {
  const perms = usePerms("project", [1, 2, 3]);
  if (perms.loading) return <p>loading</p>;
  return <ul>{[1, 2, 3].map((id) => <li key={id}>{id}:{perms(id).perms.join(",")}{perms(id).can("edit") && " [rename]"}</li>)}</ul>;
}
      <Can type="project" id={1} perm="edit" fallback={<span>no edit on 1</span>}><span>edit on 1</span></Can>
```

`useShares` and a headless `<ShareDialog>` share and unshare as the database allows; `useAccessRequest` asks
for access. They stay current over server-sent events. A request without a reason answers 400 with the
database's words, "say why you need it" (its fields: <https://rowstile.dev/problems/bad-argument>), one from
someone not signed in 401, "sign in first" (<https://rowstile.dev/problems/not-signed-in>), and a share with
someone who doesn't exist 404, "there is no user 99".

Your own code shares with `db.$authz.share`: the object, the relation, then who it is shared with (a type and
an id; for a team's members, `"team", 7, "member"`). Who may share is the policy's (`viewer : user shared by
edit`), so the handler checks nothing: anyone else gets a 403.

```ts
export const POST = route(async (req: Request, { params }: Params) => {
  const { user } = (await req.json()) as { user: number };
  await db.$authz.share("project", Number((await params).id), "viewer", "user", user);
  return new Response(null, { status: 204 });
});
```

## Next.js with pg, without Prisma

An app on plain `pg` (node-postgres) takes `@rowstile/pg` where this page has `@rowstile/prisma`; the rest
holds: `route()`, `action()`, `checkAtStart`, the React kit. Install `@rowstile/pg@next` instead of
`@rowstile/prisma@next`. The pool connects as the app role, with a URL of its own, and `authz(pool, { user })`
signs each transaction in as the request's user (`requestUser`: your session's user id, as above):

```ts
import pg from "pg";
import { authz } from "@rowstile/pg";
import "@rowstile/next";                              // signed-in reads never land in a cache

const url = process.env.ROWSTILE_APP_URL;
export const pool = new pg.Pool({ connectionString: url, max: Number(process.env.PG_POOL_MAX ?? 5) });
export const sql = authz(pool, { user: requestUser });
```

A plain query reads what the user may see. `sql.transaction(async (client) => ...)` runs several statements
signed in once, and `sql.expect(...)` says why an UPDATE or DELETE changed nothing ([Node apps](node.md#pg)):

```ts
import { route } from "@rowstile/next";
import { sql } from "@/pg";

export const GET = route(async () => {
  const { rows } = await sql.query("SELECT id FROM app.notes ORDER BY id");
  return Response.json(rows.map((r) => r.id));
});
```

A sharing dialog lists the shares, makes them and takes them back; the database decides who may (the
relation's `shared by`), and `route()` answers its refusal with 403 ("you cannot share project 1"). A share's
columns are in [the reference](../reference/app-code.md):

```ts
type Params = { params: Promise<{ id: string }> };

export const GET = route(async (_req: Request, { params }: Params) => {
  const shares = await sql.listShares("project", Number((await params).id));
  return Response.json(shares.map((s) => ({ relation: s.relation, user: s.subject_id })));
});

export const POST = route(async (req: Request, { params }: Params) => {
  const { user } = (await req.json()) as { user: number };
  await sql.share("project", Number((await params).id), "viewer", "user", user);
  return new Response(null, { status: 204 });
});
```

`sql.unshare(...)` takes the same arguments. At start-up, `checkAtStart` in `instrumentation.ts` stops the
server if the pool's connection skips row-level security (a superuser, BYPASSRLS, the tables' owner); calling
`sql.check()` there yourself only throws, which Next.js logs before it goes on serving:

```ts
export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") await checkAtStart((await import("./src/pg.ts")).sql);
}
```

## Background jobs

A job acts for a principal of its own (`type service = app.services principal` in the policy), whatever
started it: `after()`, a queue worker, a cron route.

```ts
import { current, job } from "@rowstile/client";

export const digest = job(["service", 1], async () => ({ count: await db.project.count(), who: current() }));
```

Anywhere else, `actingAs("3", () => ...)` signs in what runs inside it.

## Migrations

The policy ships as Prisma migrations. `rowstile migrate` writes the next one (only what changed since
`db/policy.lock`), and Prisma applies it with the others; Prisma's own diff then shows no change.

```sh
npx rowstile migrate --name note_comment_view   # after changing the policy: <time>_authz_note_comment_view
npx prisma migrate deploy                       # a new database, CI, production
npx rowstile migrate --check                    # in CI: exit 1 if a policy change has no migration

# the development database `rowstile dev` pushed to holds that change already: there, in place of deploy
npx prisma migrate resolve --applied 20261006215008_authz_note_comment_view   # the migration's folder
```

Without `--name` the folder is `<time>_authz_policy`.

While you edit, `npx rowstile dev` checks, pushes to the development database, runs the tests and rewrites
`src/authz.gen.ts` on every save (and writes the migration once you stop editing).

The development database then holds what `dev` (or `rowstile push`) pushed, not what its migrations left.
The first migration, the whole policy, applies over that; a later `prisma migrate deploy` stops there with
AZ607, "this database already holds what this migration brings", which Prisma keeps as a failed migration:
`resolve --applied` is what the message asks for, and it clears that too. Or rebuild the database from the
migrations. Production and CI only ever take migrations.

## Tests

The policy's own tests run with `rowstile test`. In Vitest, the matchers read the refusal:

```ts
import { expect } from "vitest";
import { matchers } from "@rowstile/vitest";

expect.extend(matchers);
```

```ts
  await expect(actingAs("3", () => db.$transaction((tx) => tx.note.update({ where: { id: 1 }, data: { body: "x" } }))))
    .rejects.toBeRefused("update", "note.edit");
  await expect(actingAs("2", () => db.note.delete({ where: { id: 1 } }))).rejects.toBeNotFound();
```

`databasePerWorker(ownerUrl)` copies the migrated test database once for each Vitest worker, so tests that
write don't meet each other. The copy needs nobody connected to the original; where the service keeps one
(Neon does, for minutes after a connection), it says so and what to use instead ([Managed
Postgres](../managed-postgres.md)).

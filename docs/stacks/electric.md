# Electric

<!-- tested: every line of code below is in integrations/electric (tests/unit_test.py checks it) -->

**Preview.** Electric on rowstile may change in any release, and is not part of what 1.0 will promise. Tell us
what doesn't fit your app.

[Electric](https://electric-sql.com) syncs shapes to clients: the rows of one table that match a filter, and
their changes as they happen. It reads Postgres by logical replication, where row-level security doesn't run. So
the policy's sync lines keep an index of who may read each row ([the sync index](../reference/sync.md)), and the
app's own server stands in front of Electric: for each request it asks the database who is asking, and sets the
shape's filter to the index's rows for them, whatever the client sent.

Everything here comes from [`integrations/electric`](../../integrations/electric), the conformance suite: a small
Express app, Electric 1.8.1, nginx as a cache in front, and the checks on Electric's own client
([`integrations/electric/test.sh`](../../integrations/electric/test.sh)). The reference is
[Electric](../reference/sync.md#electric), in the sync index's page.

## Install

```sh
# @next on each: the newest pre-release (until 0.1.0 a plain install gets it too)
npm install @rowstile/client@next @rowstile/pg@next
npm install --save-dev rowstile@next                  # the command
npm install @electric-sql/client                      # in the app's client, which asks the app's routes
```

## The policy

A sync line for each table Electric serves, and the role Electric connects as. A line with a permission syncs the
rows whose readers hold it; one without, the rows the table's select rule gives.

```authz
app role conf_app
sync role conf_electric
sync app.files : view
sync app.folders
sync app.notes
```

## Electric's role and its publication

Electric connects as a role of its own, which owns no table: it can't turn row-level security off, and it can't
add a table to a publication. Whoever runs the database makes it, as a superuser or the managed service's admin: a
role that may make roles can give neither REPLICATION nor BYPASSRLS without holding them.

```sh
# as an administrator, once
psql -c "CREATE ROLE conf_electric LOGIN PASSWORD '...' REPLICATION BYPASSRLS"
```

The rest is the app's migrations. The synced tables give Electric every column of the old row, and Electric's
role may read them, but for a column the policy masks:

```sql
-- Electric reads changes by logical replication, and asks for every column of the old row
ALTER TABLE app.files REPLICA IDENTITY FULL;
ALTER TABLE app.folders REPLICA IDENTITY FULL;
-- Electric's role reads the synced tables, and of the notes every column but the body the policy masks
GRANT USAGE ON SCHEMA app TO conf_electric;
GRANT SELECT ON app.files, app.folders TO conf_electric;
GRANT SELECT (id, file_id, author_id) ON app.notes TO conf_electric;
```

The publication comes after the policy's migration, since it names the index's tables: the synced tables, the
keys each principal holds, and the readers of each synced table.

```sql
CREATE PUBLICATION electric_publication_default FOR TABLE app.files, app.folders, authz_sync.keys,
  authz_sync.file__readers, authz_sync.folder__readers;
```

Electric runs in its manual publication mode, on its own role, with a secret only the app's server knows, and
Postgres with `wal_level = logical`:

```sh
docker run -e DATABASE_URL="postgresql://conf_electric:...@db:5432/app" \
  -e ELECTRIC_MANUAL_TABLE_PUBLISHING=true -e ELECTRIC_SECRET=... electricsql/electric:1.8.1
```

The notes aren't in the publication. Electric asks for every column of the old row, so a publication of the notes
would carry the body the policy masks to Electric, and `authz.lint()` says so. Keep such a column in a table of its
own, which isn't synced.

## The shapes: `rowstile client electric`

`rowstile client electric` writes each synced table's shape as TypeScript constants: its table, its key columns,
the columns the policy masks, and the index's filter for each type that signs in. Under `[clients]` in
`rowstile.toml`, `rowstile client` and `rowstile dev` write it with the other clients:

```toml
[clients]
ts       = "src/authz.gen.ts"
electric = "src/shapes.gen.ts"
```

```sh
npx rowstile client electric > src/shapes.gen.ts     # or rowstile client, with the line above
```

It holds the policy's names and the filter's text, nothing else. Write it again when the policy changes; the
conformance suite fails when it is out of date.

## The route: `electricShape` and `syncPrincipal`

`electricShape(shape, options)` is a route handler, fetch's `Request` to its `Response`, for GET and POST (a
subset). `signedIn` asks the database who the request is, in the app's own way: `syncPrincipal(c)` in a
transaction signed in as the request's user, or after `authz.login_key()` for an API key. It answers who signed
in, and whether the session is limited (`authz.session_limited()`).

```ts
import { actingAs, electricShape, problemOf, syncPrincipal, type ElectricShape } from "@rowstile/client";
import { shapes } from "./shapes.gen.js";

// who the request is, asked of the database the app's way: an API key signs in with it, else the session's user
export async function signedIn(req: Request) {
  const key = keyOf(req.headers);
  if (key !== null) {
    return sql.transaction(async (c) => {
      await c.query("SELECT authz.login_key($1)", [key]);
      return syncPrincipal(c);
    });
  }
  return actingAs(userOf(req.headers), () => sql.transaction((c) => syncPrincipal(c)));
}
```

`userOf` is your session's user: your own cookie or token, or Passport's `req.user`. A route for each synced
table, on Electric's shape endpoint (`http://electric:3000/v1/shape`, which only the server reaches):

```ts
const electric = { url: process.env.ELECTRIC_URL ?? "", secret: process.env.ELECTRIC_SECRET, signedIn, vary: [USER, KEY] };
// a Map, so that a name such as constructor finds no route
export const routes = new Map<string, (req: Request) => Promise<Response>>([
  ["files", electricShape(shapes["app.files"], electric)],
  ["folders", electricShape(shapes["app.folders"], electric)],
  // the policy masks the notes' body: the columns to sync leave it out
  ["notes", electricShape(shapes["app.notes"] satisfies ElectricShape, { ...electric, columns: ["id", "file_id", "author_id"] })],
]);
```

Express hands each route fetch's `Request` (the app's `fetched`, in `src/app.ts`); a framework whose route
handlers take fetch's `Request` (a Next.js route handler, Hono) takes the route as it is, for GET and POST:

```ts
app.all("/shapes/:table", async (req, res, next) => {
  const handler = routes.get(String(req.params.table));
  if (typeof handler !== "function") return next();
  await fetched(handler, req, res);
});
```

For each request the route:

- answers 401 (AZ714) for nobody, and asks nothing of Electric;
- answers 403 (AZ704) for a session limited by scopes (a key's, a token's) or viewing as someone: the index holds
  what each principal may read, without scopes;
- sets the shape's `table`, `where`, `params[1]` (the principal's id) and Electric's `secret` itself;
- refuses a client's own `where`, `params`, another `table`, `queryable_columns` or `secret`, 400 (AZ710). A
  client narrows with Electric's subsets instead (`subset__where`, or a POST's body), which Electric adds to the
  filter with AND;
- refuses a POST whose body is more than a subset, 400;
- always syncs the key columns, and never a masked one: a table the policy masks a column of needs `columns`,
  which leave it out (the route refuses to be set up without them).

The client asks the app's route, never Electric: `@electric-sql/client`'s `ShapeStream` with the route's URL
(`/shapes/files`), and the session's cookie.

## `Vary` and a cache

Electric's answers can be cached, and a CDN or a proxy in front of the app may keep them. `vary` names the request
headers that tell one user from another: the route answers with `Vary` on them (and on Electric's own), so a
cache keeps a copy for each user and never gives one user's shape to another. In your app it is the session's
cookie (`vary: ["cookie"]`), or `authorization` for a token. The route refuses to be set up without it. Its own
refusals (401, 403, 400) say `cache-control: no-store`.

The conformance suite puts nginx in front of the app, keyed on the URL, and checks that two users asking for the
same URL each get their own shape, and the cache answers each from their own copy.

## What can't be done

- **Rows already on a device stay there** while it is offline, and in any copy the client keeps. A revoke stops
  delivery: Electric sends a move-out, which the client must apply. Electric's own `Shape` class
  (`@electric-sql/client` 1.5.28) doesn't: it keeps the row until the shape is fetched again. Read the stream's
  move-out events, or use a client that applies them.
- **The window after a change** is Electric's replication lag, and for a share that ends, until the next
  `authz.sync_tick()` too: schedule it ([Retention](../operations.md#retention)).
- **Scoped sessions are refused.** The index holds what each principal may read, without a key's or a token's
  scopes, so a session limited by them (or viewing as someone) gets 403.
- **What the index leaves out gives nothing through Electric:** shares with a caveat, links, scopes.
- **A client's own filter** is refused: only Electric's subsets narrow a shape, and a POST whose body is more than
  a subset is refused.
- **A table with a masked column can't be published whole**: keep the column in a table of its own.
- **Electric is trusted.** It holds BYPASSRLS and every row of what it publishes, and rowstile can't check what it
  serves. The conformance suite checks it end to end, for the forms it uses.

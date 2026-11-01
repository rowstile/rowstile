# Zero

<!-- tested: every line of code below is in integrations/zero (tests/unit_test.py checks it) -->

**Preview.** Zero on rowstile may change in any release, and is not part of what 1.0 will promise. Tell us what
doesn't fit your app.

[Zero](https://zero.rocicorp.dev) syncs queries to clients: a client asks for a named query, zero-cache asks the
app's server for its ZQL, runs it on its replica of the database, and keeps the client's copy current. zero-cache
reads Postgres by logical replication, where row-level security doesn't run. So the policy's sync lines keep an
index of who may read each row ([the sync index](../reference/sync.md)), and the app's query endpoint adds the
index's filter to each query, for whoever the request signs in as.

Everything here comes from [`integrations/zero`](../../integrations/zero), the conformance suite: a small Express
app with Zero's two endpoints, zero-cache 1.11.0, and the checks on Zero's own client, in Node
([`integrations/zero/test.sh`](../../integrations/zero/test.sh)). The reference is
[Zero](../reference/sync.md#zero), in the sync index's page.

## Install

```sh
# @next on each: the newest pre-release (until 0.1.0 a plain install gets it too)
npm install @rowstile/client@next @rowstile/pg@next @rocicorp/zero
npm install --save-dev rowstile@next                  # the command
```

## The policy

A sync line for each table Zero serves, and the role zero-cache connects as. A line with a permission syncs the rows
whose readers hold it; one without, the rows the table's select rule gives.

```authz
app role conf_app
sync role conf_zero
sync app.files : view
sync app.folders
sync app.notes
```

## Zero's role and its publication

zero-cache connects as a role of its own, which owns no table of the app's. Whoever runs the database makes it, as
a superuser or the managed service's admin: a role that may make roles can give neither REPLICATION nor BYPASSRLS
without holding them. zero-cache runs without event triggers (only a superuser may make them): a plain apply
changes nothing it replicates, but a sync line added or dropped does, and zero-cache then resets, unless you call
Zero's schema change hook.

```sh
# as an administrator, once
psql -c "CREATE ROLE conf_zero LOGIN PASSWORD '...' REPLICATION BYPASSRLS"
```

The rest is the app's migrations. Zero reads each row by its primary key, so the tables keep their default replica
identity, and Zero's role may read them, but for a column the policy masks:

```sql
-- Zero's role reads the synced tables, and of the notes every column but the body the policy masks
GRANT USAGE ON SCHEMA app TO conf_zero;
GRANT SELECT ON app.files, app.folders TO conf_zero;
GRANT SELECT (id, file_id, author_id) ON app.notes TO conf_zero;
```

The publication comes after the policy's migration, since it names the index's tables: the synced tables, of the
notes every column but the masked body, the keys each principal holds, and the readers of each synced table. Zero's
role may create in the database, for its own schemas.

```sql
CREATE PUBLICATION zero_data FOR TABLE app.files, app.folders, app.notes (id, file_id, author_id), authz_sync.keys,
  authz_sync.file__readers, authz_sync.folder__readers, authz_sync.note__readers;
DO $$ BEGIN EXECUTE format('GRANT CREATE ON DATABASE %I TO conf_zero', current_database()); END $$;
```

zero-cache runs on its own role, the publication named, with the app's two endpoints, and Postgres with
`wal_level = logical`. Once it has made its schemas, Zero's role lets the app role write Zero's record of each
client's mutations, which the mutate endpoint keeps in each mutation's transaction:

```sh
docker run -e ZERO_UPSTREAM_DB="postgresql://conf_zero:...@db:5432/app" \
  -e ZERO_CVR_DB="postgresql://conf_zero:...@db:5432/app" -e ZERO_CHANGE_DB="postgresql://conf_zero:...@db:5432/app" \
  -e ZERO_APP_PUBLICATIONS=zero_data -e ZERO_QUERY_URL=https://app/api/zero/query \
  -e ZERO_MUTATE_URL=https://app/api/zero/mutate -e ZERO_ADMIN_PASSWORD=... rocicorp/zero:1.11.0
psql -U conf_zero -c "GRANT USAGE ON SCHEMA zero_0 TO conf_app" \
  -c "GRANT SELECT, INSERT, UPDATE ON zero_0.clients, zero_0.mutations TO conf_app"
```

## The index as Zero sees it: `rowstile client zero`

`rowstile client zero` writes a TypeScript module for the app's Zero schema: the index's tables as Zero tables and
their relationships, the relationship each synced table needs to its readers, the columns the policy masks, and each
table's filter. Under `[clients]` in `rowstile.toml`, `rowstile client` and `rowstile dev` write it with the other
clients:

```toml
[clients]
ts       = "src/authz.gen.ts"
zero     = "src/zero.gen.ts"
```

The app's Zero schema holds its own tables, never a masked column, each with its `readers`, and the index's:

```ts
import { readers, syncRelationships, syncTables } from "./zero.gen.js";

const note = table("note").from("app.notes")
  .columns({ id: number(), file_id: number(), author_id: number() })
  .primaryKey("id");

export const schema = createSchema({
  tables: [file, folder, note, ...syncTables],
  relationships: [
    relationships(file, ({ many }) => ({ readers: many(readers["app.files"]) })),
    relationships(folder, ({ many }) => ({ readers: many(readers["app.folders"]) })),
    relationships(note, ({ many }) => ({ readers: many(readers["app.notes"]) })),
    ...syncRelationships,
  ],
});
```

Each query adds its table's filter for whoever the context says, which the query endpoint makes:

```ts
export const queries = defineQueries({
  files: defineQuery(({ ctx }) => readable["app.files"](zql.file, ctx).orderBy("id", "asc")),
  folders: defineQuery(({ ctx }) => readable["app.folders"](zql.folder, ctx).orderBy("id", "asc")),
  notes: defineQuery(({ ctx }) => readable["app.notes"](zql.note, ctx).orderBy("id", "asc")),
});
```

## The endpoints

zero-cache calls them with the client's token. Each asks the database who the request is, in the app's own way
(here, a key signs in with `authz.login_key()`, else the token's user), with `syncPrincipal` from
`@rowstile/client`:

```ts
export async function signedIn(token: Token): Promise<SyncPrincipal> {
  if (token !== null && "key" in token) {
    return sql.transaction(async (c) => {
      await c.query("SELECT authz.login_key($1)", [token.key]);
      return syncPrincipal(c);
    });
  }
  return actingAs(token?.user ?? null, () => sql.transaction((c) => syncPrincipal(c)));
}
```

Nobody is 401, and a session limited by scopes or viewing as someone 403, which Zero shows the client as
`needs-auth`. Otherwise the query endpoint returns each query's ZQL, its context made from the request, never the
client's:

```ts
  const result = await handleQueryRequest({
    handler: (name, args) => mustGetQuery(queries, name).fn({ args, ctx: asked.ctx }),
    schema,
    request: fetchRequest(req),
    userID: asked.ctx.id,
  });
```

The mutate endpoint signs each mutation's transaction in as the request's user before the mutator runs, so the
rules decide what it may write:

```ts
      transact(async (tx, name, args) => {
        // the transaction signed in first, as the request's key or user: what the mutator writes, the rules judge
        if (token !== null && "key" in token) await tx.dbTransaction.query("SELECT authz.login_key($1)", [token.key]);
        else {
          const signIn = actAs({ type: ctx.type, id: ctx.id });
          await tx.dbTransaction.query(signIn.text, signIn.values);
        }
        return mustGetMutator(mutators, name).fn({ args, tx, ctx });
      }),
```

Its server schema holds the app's own tables only: Zero checks a server schema's tables against those its
connection holds a privilege on, and the app role holds none on the index.

```ts
export const writeSchema = createSchema({ tables: [file, folder, note] });
```

Zero's own update doesn't count the rows it changed, and row-level security makes an update of a row the user may
not update change none. On the server, write it as SQL and hand its result to the SDK's `expect`, which says
whether the row was hidden or refused, and why; the client keeps Zero's own update, for its copy:

```ts
    rename: defineMutator<{ id: number; name: string }>(async ({ tx, args }) => {
      if (tx.location !== "server") return tx.mutate.file.update({ id: args.id, name: args.name });
      const db = { query: async (text: string, values: unknown[]) => ({ rows: [...await tx.dbTransaction.query(text, values)] }) };
      await calls(db).expect(await db.query("UPDATE app.files SET name = $1 WHERE id = $2 RETURNING id", [args.name, args.id]),
        "app.files", "update", args.id);
    }),
```

## What can't be done

- Rows already on a device stay there while it is offline, and in any copy the client keeps. A revoke stops
  delivery, and Zero removes the row when the client next syncs.
- The window after a change is zero-cache's replication lag, and for a share that ends, until the next
  `authz.sync_tick()` too.
- A client syncs the rows its queries read, the index's among them: its own keys and the readers rows they lead to,
  never another user's key.
- zero-cache is trusted: it holds BYPASSRLS and every row of what it publishes. rowstile can't check what it
  serves; the conformance suite checks it end to end.

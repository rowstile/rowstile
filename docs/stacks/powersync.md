# PowerSync

<!-- tested: every line of code below is in integrations/powersync (tests/unit_test.py checks it) -->

**Preview.** PowerSync on rowstile may change in any release, and is not part of what 1.0 will promise. Tell us
what doesn't fit your app.

[PowerSync](https://www.powersync.com) syncs streams to clients: the PowerSync service runs each stream's query on
its replica of the database, puts each row in buckets keyed by a value on the row, and each client gets the buckets
its token names. The service reads Postgres by logical replication, where row-level security doesn't run. So the
policy's sync lines keep an index of who may read each row ([the sync index](../reference/sync.md)), and `mirrored`
keeps each synced table's rows with their readers on them, which the streams put in a bucket for each key.

Everything here comes from [`integrations/powersync`](../../integrations/powersync), the conformance suite: a small
Express app that gives the clients their tokens and takes their writes, the PowerSync service 1.27.0, and the checks
on PowerSync's own client in Node ([`integrations/powersync/test.sh`](../../integrations/powersync/test.sh)). The
reference is [PowerSync](../reference/sync.md#powersync), in the sync index's page.

## Install

```sh
# @next on each: the newest pre-release (until 0.1.0 a plain install gets it too)
npm install @rowstile/client@next @rowstile/pg@next
npm install --save-dev rowstile@next                  # the command
npm install @powersync/node better-sqlite3            # in a Node client; the web's is @powersync/web
```

## The policy

A sync line for each table PowerSync serves, each `mirrored`, and the role the service connects as.

```authz
app role conf_app
sync role conf_ps
sync app.files : view mirrored
sync app.folders mirrored
sync app.notes mirrored
```

Each mirror (`authz_sync.file__mirror`) holds the table's rows, every column but those the policy masks (the notes'
body), and `readers`, the keys that may read the row.

## PowerSync's role and its publication

The service connects as a role of its own, which reads the mirrors and owns nothing of the app's. Whoever runs the
database makes it, as a superuser or the managed service's admin, and the database it keeps its buckets in:

```sh
# as an administrator, once
psql -c "CREATE ROLE conf_ps LOGIN PASSWORD '...' REPLICATION BYPASSRLS" -c "CREATE DATABASE conf_ps_storage OWNER conf_ps"
```

The publication is the app's migration, after the policy's, which makes the mirrors. It must be named powersync:

```sql
CREATE PUBLICATION powersync FOR TABLE authz_sync.file__mirror, authz_sync.folder__mirror, authz_sync.note__mirror,
  authz_sync.keys;
```

## The streams: `rowstile client powersync`

`rowstile client powersync` writes the service's sync config: a stream for each mirrored table, its columns read from
the database (the mirror's, never `readers`). Under `[clients]` in `rowstile.toml`, `rowstile client` writes it with
the other clients, reading the database `rowstile.toml` names:

```toml
[clients]
ts        = "src/authz.gen.ts"
powersync = "powersync/sync-config.yaml"
```

```yaml
config:
  edition: 3
streams:
  files:
    auto_subscribe: true
    query: |
      SELECT files."id", files."folder_id", files."owner_id", files."name", files."confidential"
      FROM authz_sync."file__mirror" files, json_each(files.readers) r
      WHERE r.value IN (SELECT key FROM authz_sync.keys
                        WHERE principal_type = ifnull(auth.parameter('principal_type'), 'user')
                          AND principal_id = auth.user_id())
```

Each client gets a bucket for each key its principal holds, a few, never one for each row. The service's config names
the publication's database, its storage, the streams, and the key it checks tokens with:

```sh
docker run -v ./config:/config -e POWERSYNC_CONFIG_PATH=/config/service.yaml journeyapps/powersync-service:1.27.0 start -r unified
```

## The token

The app gives each client its token, after asking the database who the request is, in the app's own way (here, a
key signs in with `authz.login_key()`, else the session's user), with `syncPrincipal` from `@rowstile/client`:

```ts
export async function signedIn(headers: Headers): Promise<SyncPrincipal> {
  const key = keyOf(headers);
  if (key !== null) {
    return sql.transaction(async (c) => {
      await c.query("SELECT authz.login_key($1)", [key]);
      return syncPrincipal(c);
    });
  }
  return actingAs(userOf(headers), () => sql.transaction((c) => syncPrincipal(c)));
}
```

Nobody gets no token (401), nor does a session limited by scopes or viewing as someone (403): the index holds what
each principal may read, without scopes. The token names the principal: `sub` its id, `principal_type` its type.

```ts
    const who = await signedIn(headersOf(req));
    if (who.id === null) {
      res.status(401).json({ error: "Unauthorized", detail: "sign in to sync" });
      return;
    }
    if (who.limited) {
      res.status(403).json({ error: "Forbidden", detail: "a session limited by scopes, or viewing as someone, can't sync" });
      return;
    }
    res.json({ token: token({ type: who.type, id: who.id }) });
```

The clients' writes come back through the app's own routes, signed in as the request's user, so the database refuses
what they may not write: a refused one is the app's 403, with the rule and why.

## What can't be done

- Rows already on a device stay there while it is offline, and in any copy the client keeps. A revoke stops
  delivery, and the row leaves the client once it is in none of its buckets.
- The window after a change is the service's replication lag, and for a share that ends, until the next
  `authz.sync_tick()` too.
- A mirrored line can't be keyed by folder (AZ811): a move rewrites the readers of what is below it.
- The service is trusted: it holds BYPASSRLS and every row of what it publishes. rowstile can't check what it
  serves; the conformance suite checks it end to end.

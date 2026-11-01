// Electric's conformance suite (a preview): every user's shapes of the files and the folders, live through the app's
// proxy, held after each change to what authz.list gives them (the oracle), with the ids. test.sh does check 11 (a
// fresh database: migrate, the policy's tests, the lock file) and 13 (the server refuses the owner's connection), and
// starts the servers, Electric and the cache these checks call.
//
// The checks run whole in each of the index's modes (SYNC_MODE, which test.sh reads): copied in, keyed by folder, and
// after commit, where a worker beside the app runs authz.sync_work() in a loop. The oracle answers at once, and the
// shapes follow once the index does: a check waits for the shape's next messages, whatever the mode. Where it needs
// the index to hold every change made so far before it asks (a snapshot, a state that must not have changed yet),
// it waits for the worker's next run first (settled()): after commit, that is when the index has them.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, expect, test } from "vitest";
import type { Server } from "node:http";
import { app } from "../src/app.js";
import { pool, sql } from "../src/db.js";
import { shapes } from "../src/shapes.gen.js";
import { syncWorker, type SyncWorker } from "../src/worker.js";
import { CACHE, ELECTRIC, Live, MODE, OWNER, POLICY, SERVER, SERVER_ONE, USERS, as, asUser, direct, idsOf, listed, owner, run,
  seed } from "./data.js";

const HERE = join(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(HERE, "..", "..", "core", "cli", "rowstile_cli.py");
const rowstile = (...args: string[]) =>
  execFileSync(process.env.PYTHON ?? "python3", [CLI, ...args], { cwd: HERE, encoding: "utf8", stdio: "pipe" });

const live: Record<string, { file: Live; folder: Live }> = {};
/** After commit, the worker, run as the policy's owner: the app role can't call authz.sync_work() */
let worker: SyncWorker | null = null;
/** After commit, once the worker's next run has ended: the index holds every change committed before; else at once. */
const settled = async (): Promise<void> => worker?.ran();

/** Every user's shapes hold what authz.list gives them, of the files and of the folders. */
async function asListed(): Promise<void> {
  for (const user of USERS) {
    await live[user]!.file.holds(await listed(user, "file"));
    await live[user]!.folder.holds(await listed(user, "folder"));
  }
}

let server: Server;
beforeAll(async () => {
  await sql.check();                                             // as src/server.ts does, before it listens
  server = await new Promise<Server>((resolve) => {
    const s = app.listen(Number(process.env.CONFORMANCE_APP_PORT), "127.0.0.1", () => resolve(s));
  });
  await seed();
  // after commit, the shapes open once the worker has worked the world in: Electric 1.8.1 can drop a shape opened
  // while its filter's tables are written (its subquery's materializer meets a row twice, "Key ... already exists"),
  // and the client then gets must-refetch and syncs the shape again
  if (MODE === "after") worker = syncWorker(OWNER);
  await settled();
  for (const user of USERS) live[user] = { file: new Live(user, "files"), folder: new Live(user, "folders") };
});
afterAll(async () => {
  await worker?.stop();
  for (const l of Object.values(live)) {
    l.file.close();
    l.folder.close();
  }
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
  await pool.end();
});

// The index in force is in the mode test.sh set up: keyed by folder, the folders' group keys; after commit, the table
// of what waits for the worker; copied in, neither
test(`the index is kept in the mode the suite runs in (${MODE})`, async () => {
  const [mode] = (await run(`SELECT EXISTS (SELECT 1 FROM authz_sync.keys WHERE key LIKE 'folder#%') AS keyed,
    to_regclass('authz_sync.pending') IS NOT NULL AS after`)).rows as { keyed: boolean; after: boolean }[];
  expect(mode).toEqual({ keyed: MODE === "keyed", after: MODE === "after" });
});

// E1 (and the stack's 1): signed in, each shape holds exactly what authz.list gives the user, from the first snapshot
test("E1: the first snapshot of each user's shapes is what authz.list gives them", async () => {
  expect(await listed("2", "file")).toEqual([1, 2, 3, 6]);       // the oracle as the world says, once
  expect(await listed("3", "file")).toEqual([5]);
  await asListed();
  expect(live["5"]!.file.ids()).toEqual([4, 5]);
});

test("E2: a share made: the row arrives live; revoked: it leaves", async () => {
  const unshare = "SELECT authz.act_as('user', '5'); SELECT authz.unshare('file', '4', 'viewer', 'user', '2')";
  try {
    await run("SELECT authz.act_as('user', '5'); SELECT authz.share('file', '4', 'viewer', 'user', '2')");
    await live["2"]!.file.holds([1, 2, 3, 4, 6]);
    await asListed();
    await run(unshare);
    await live["2"]!.file.holds([1, 2, 3, 6]);
    await asListed();
  } finally {
    await run(unshare);
  }
});

// Electric sends a move-out, not a delete, when a row leaves a shape through its subquery: a client must apply it
test("Electric's own Shape keeps a row that moved out", async () => {
  const unshare = "SELECT authz.act_as('user', '5'); SELECT authz.unshare('file', '4', 'viewer', 'user', '3')";
  try {
    await run("SELECT authz.act_as('user', '5'); SELECT authz.share('file', '4', 'viewer', 'user', '3')");
    await live["3"]!.file.holds([4, 5]);
    expect(live["3"]!.file.shapeIds()).toEqual([4, 5]);
    await run(unshare);
    await live["3"]!.file.holds([5]);
    expect(live["3"]!.file.shapeIds()).toEqual([4, 5]);           // @electric-sql/client 1.5.28: still there
  } finally {
    await run(unshare);
  }
});

test("E3: a folder moved out of reach: the files below it leave; moved back: they return", async () => {
  try {
    await run("UPDATE app.folders SET parent_id = NULL WHERE id = 2");
    await live["4"]!.file.holds([1]);                            // dee read them through eng, given the folder above
    await live["2"]!.file.holds([1, 6]);                         // bo keeps file 6: it is shared with him too
    await live["4"]!.folder.holds([1]);
    await asListed();
  } finally {
    await run("UPDATE app.folders SET parent_id = 1 WHERE id = 2");
  }
  await live["4"]!.file.holds([1, 2, 3, 6]);
  await asListed();
});

test("E4: a team left: the rows reached only through it leave, and one also reached another way stays", async () => {
  try {
    await run("DELETE FROM app.team_members WHERE team_id = 2 AND user_id = 2");
    await live["2"]!.file.holds([6]);
    await live["2"]!.folder.holds([]);
    await asListed();
  } finally {
    await run("INSERT INTO app.team_members VALUES (2, 2) ON CONFLICT DO NOTHING");
  }
  await live["2"]!.file.holds([1, 2, 3, 6]);
  await asListed();
});

test("E5: a sub-team moved under another team: its members' rows follow", async () => {
  try {
    await run("UPDATE app.teams SET parent_id = 3 WHERE id = 2");  // backend, out of eng, into ops
    await live["2"]!.file.holds([5, 6]);
    await live["2"]!.folder.holds([4]);
    await live["4"]!.file.holds([1, 2, 3, 6]);                   // dee is in eng itself
    await asListed();
  } finally {
    await run("UPDATE app.teams SET parent_id = 1 WHERE id = 2");
  }
  await live["2"]!.file.holds([1, 2, 3, 6]);
  await asListed();
});

test("E6: a share that ends: the row leaves at the next authz.sync_tick(), and not before", async () => {
  const [{ ends }] = (await run(`SELECT authz.act_as('user', '5');
    SELECT authz.share('file', '4', 'viewer', 'user', '3', '', now() + interval '1 second');
    SELECT expires_at AS ends FROM authz.shares WHERE object_id = '4' AND subject_id = '3'`) as unknown as { rows: { ends: Date }[] }[])[2]!.rows;
  await live["3"]!.file.holds([4, 5]);
  // the end passes (the database's clock): authz.list no longer gives it, the index still does until the tick
  await run("SELECT pg_sleep_until($1::timestamptz)", [ends]);
  expect(await listed("3", "file")).toEqual([5]);
  await settled();                                               // after commit: the worker ran since, and kept it
  // a write after the end, which cy reads: once it has arrived, so has everything committed before it
  await run("UPDATE app.files SET name = 'after the end' WHERE id = 5");
  await live["3"]!.file.until((l) => l.row(5)?.name === "after the end", "the rename");
  expect(live["3"]!.file.ids()).toEqual([4, 5]);                 // the stated window: until the tick
  const [{ ticked }] = (await run("SELECT authz.sync_tick() AS ticked")).rows as { ticked: string }[];
  expect(Number(ticked)).toBeGreaterThanOrEqual(1);
  await live["3"]!.file.holds([5]);                              // after commit: the tick notes it, the worker works it in
  await asListed();
});

test("E7: confidential set: the file leaves those who saw it only through its folder", async () => {
  try {
    await run("UPDATE app.files SET confidential = true WHERE id = 3");
    await live["2"]!.file.holds([1, 2, 6]);
    await live["4"]!.file.holds([1, 2, 6]);
    await live["1"]!.file.holds([1, 2, 3, 6]);                   // ann may edit it: she still reads it
    await asListed();
  } finally {
    await run("UPDATE app.files SET confidential = false WHERE id = 3");
  }
  await live["2"]!.file.holds([1, 2, 3, 6]);
  await asListed();
});

// E8 (and the stack's 5): many users at once on one Electric, in rounds: each gets their own rows, and what a client
// sends of the shape's definition is refused, while a subset only narrows
test("E8: users at once, in rounds, each get their own; a client's own filter, user id or table is refused", async () => {
  const snapshot = (user: string, query = "") =>
    fetch(`${SERVER}/shapes/files?offset=-1${query}`, { headers: as(user) });
  await settled();                                               // snapshots, held to the oracle
  for (let round = 0; round < 5; round++) {
    const users = [...USERS, ...USERS, ...USERS];
    const got = await Promise.all(users.map(async (u) => [u, await idsOf(await snapshot(u))] as const));
    for (const [u, ids] of got) expect([u, ids]).toEqual([u, await listed(u, "file")]);
  }
  for (const forged of ["&where=true", "&params%5B1%5D=1", "&params=1", "&table=app.users", "&secret=x",
                        "&queryable_columns=id"]) {
    const r = await snapshot("3", forged);
    expect([forged, r.status]).toEqual([forged, 400]);
    expect(await r.json()).toMatchObject({ type: "https://rowstile.dev/problems/bad-argument", status: 400, code: "AZ710" });
  }
  // the route's own table, said again, is no change, nor is a parameter Electric doesn't take (left out); a client
  // may narrow the columns, the key always with them; a subset narrows what the user may read, and never widens it
  expect(await idsOf(await snapshot("3", "&table=app.files&page=2"))).toEqual([5]);
  const named = (await (await snapshot("3", "&columns=name")).json()) as { value?: Record<string, string> }[];
  expect(named.filter((m) => m.value).map((m) => Object.keys(m.value ?? {}).sort())).toEqual([["id", "name"]]);
  const handle = (await snapshot("2", "&log=changes_only")).headers.get("electric-handle") ?? "";
  const subset = (where: string) => fetch(`${SERVER}/shapes/files?offset=-1&log=changes_only&handle=${handle}` +
    `&subset__where=${encodeURIComponent(where)}`, { headers: as("2") });
  const rows = async (r: Response) =>
    ((await r.json()) as { data: { value: { id: string } }[] }).data.map((m) => Number(m.value.id)).sort((a, b) => a - b);
  expect(await rows(await subset("id > 2"))).toEqual([3, 6]);
  expect(await rows(await subset("true"))).toEqual([1, 2, 3, 6]);
  expect((await subset("id IN (SELECT id FROM app.files)")).status).toBe(400);     // Electric: no subquery in a subset
  // ... and a POST's body is a subset and nothing more: one that holds anything else is refused before it reaches
  // Electric
  const post = (body: unknown) => fetch(`${SERVER}/shapes/files?offset=-1&log=changes_only&handle=${handle}`,
    { method: "POST", headers: { ...as("2"), "content-type": "application/json" }, body: JSON.stringify(body) });
  const narrowed = await post({ where: "id < $1", params: { "1": "3" } });
  expect([narrowed.status, await rows(narrowed)]).toEqual([200, [1, 2]]);
  for (const body of [{ subset: { where: "true" }, where: "true" }, { where: "true", table: "app.users" },
                      { where: "true", columns: "id" }, [1], "x", null]) {
    const r = await post(body);
    expect([body, r.status]).toEqual([body, 400]);
  }
  const garbled = await fetch(`${SERVER}/shapes/files?offset=-1&log=changes_only&handle=${handle}`,
    { method: "POST", headers: as("2"), body: "{" });
  expect(garbled.status).toBe(400);
  // the shapes stayed each user's own, live, all along
  await asListed();
});

// E9 (and the stack's 3, the proxy's way): not signed in: 401 with the problem body, and nothing asked of Electric
test("E9: not signed in: 401, and no shape is made", async () => {
  const r = await fetch(`${SERVER}/shapes/files?offset=-1`);
  expect(r.status).toBe(401);
  expect(r.headers.get("content-type")).toMatch(/^application\/problem\+json/);
  expect(await r.json()).toEqual({ type: "https://rowstile.dev/problems/not-signed-in", title: "Unauthorized",
    status: 401, detail: "sign in to sync app.files", code: "AZ714" });
  expect(r.headers.get("electric-handle")).toBeNull();           // the answer is the proxy's: Electric wasn't asked
  // ... nor for a user who isn't in the users table
  expect((await fetch(`${SERVER}/shapes/files?offset=-1`, { headers: as("99") })).status).toBe(401);
  // a route for a table nothing syncs is none of the proxy's, and another method than GET or POST isn't Electric's
  expect((await fetch(`${SERVER}/shapes/users?offset=-1`, { headers: as("1") })).status).toBe(404);
  // ... nor is a name every object has (the routes are a Map, not an object's properties)
  for (const name of ["constructor", "toString", "__proto__"]) {
    expect((await fetch(`${SERVER}/shapes/${name}?offset=-1`, { headers: as("1") })).status).toBe(404);
  }
  const deleting = await fetch(`${SERVER}/shapes/files?offset=-1`, { method: "DELETE", headers: as("1") });
  expect([deleting.status, deleting.headers.get("allow")]).toEqual([405, "GET, POST"]);
});

// E10: a shared cache in front of the app keeps a copy per user (the answers vary on the headers that say who)
test("E10: answers vary on who asks, and a cache never gives one user's shape to another", async () => {
  await settled();                                               // snapshots, held to the oracle
  const r = await fetch(`${SERVER}/shapes/files?offset=-1`, { headers: as("1") });
  expect(r.headers.get("vary")?.split(", ")).toEqual(expect.arrayContaining(["x-user", "x-api-key"]));
  expect(r.headers.get("cache-control")).toMatch(/public/);     // Electric's: a cache may keep it, as each user's
  const url = `${CACHE}/shapes/files?offset=-1&cache-buster=${Date.now()}`;
  const first = await fetch(url, { headers: as("1") });
  const again = await fetch(url, { headers: as("1") });
  const other = await fetch(url, { headers: as("3") });
  const nobody = await fetch(url);
  expect([first.headers.get("x-cache"), again.headers.get("x-cache")]).toEqual(["MISS", "HIT"]);   // it does cache
  expect(await idsOf(first)).toEqual(await listed("1", "file"));
  expect(await idsOf(again)).toEqual(await listed("1", "file"));
  expect([other.headers.get("x-cache"), await idsOf(other)]).toEqual(["MISS", await listed("3", "file")]);
  expect(nobody.status).toBe(401);
});

// E11: writes through the app, as its users: an allowed one arrives in the shapes of those who may read the row; a
// refused one is 403 with the reason, a hidden row 404
test("E11: writes through the app arrive in the shapes", async () => {
  try {
    const post = await fetch(`${SERVER}/api/files`, { method: "POST", headers: { ...as("1"), "content-type": "application/json" },
      body: JSON.stringify({ id: 7, folder_id: 2, name: "new" }) });
    expect(post.status).toBe(201);
    await live["2"]!.file.holds([1, 2, 3, 6, 7]);
    await live["1"]!.file.holds([1, 2, 3, 6, 7]);
    const rename = (user: string, id: number) => fetch(`${SERVER}/api/files/${id}`,
      { method: "PATCH", headers: { ...as(user), "content-type": "application/json" }, body: JSON.stringify({ name: "renamed" }) });
    expect((await rename("1", 7)).status).toBe(200);
    await live["2"]!.file.until((l) => l.row(7)?.name === "renamed", "file 7 renamed");
    const refused = await rename("2", 7);                          // bo reads file 7, but may not edit it
    expect([refused.status, ((await refused.json()) as { code: string }).code]).toEqual([403, "AZ709"]);
    expect((await rename("2", 4)).status).toBe(404);              // eve's file: bo can't see it
    const into = await fetch(`${SERVER}/api/files`, { method: "POST", headers: { ...as("2"), "content-type": "application/json" },
      body: JSON.stringify({ id: 8, folder_id: 2, name: "bo's" }) });
    expect([into.status, ((await into.json()) as { code: string }).code]).toEqual([403, "AZ709"]);
    await asListed();
  } finally {
    await run("DELETE FROM app.files WHERE id = 7");
  }
  await live["2"]!.file.holds([1, 2, 3, 6]);
});

// E12: lint finds an Electric role that breaks the rules; applying and applying again leave the shapes as they are
// (no 409, no must-refetch), and the index agrees with a rebuild
test("E12: lint, then rowstile apply and reapply leave the shapes as they are", async () => {
  const errors = async () => ((await run("SELECT object || ': ' || problem AS p FROM authz.lint() WHERE severity = 'error'"))
    .rows as { p: string }[]).map((r) => r.p);
  expect(await errors()).toEqual([]);
  // the shapes as E12 starts: their handles, and how many controls each was sent so far
  const handles = Object.fromEntries(USERS.map((u) => [u, live[u]!.file.stream.shapeHandle]));
  const sent = Object.fromEntries(USERS.map((u) => [u, live[u]!.file.controls.length]));
  // as whoever runs the database: what the app's owner can't do to a role
  const admin = (sql: string) => owner((c) => c.query(sql), process.env.ROWSTILE_ADMIN_DSN ?? "");
  for (const [broken, mended, says] of [
    ["ALTER ROLE conf_electric NOBYPASSRLS", "ALTER ROLE conf_electric BYPASSRLS", "BYPASSRLS"],
    ["GRANT conf_app TO conf_electric", "REVOKE conf_app FROM conf_electric", "one another's members"],
    ["GRANT SELECT (body) ON app.notes TO conf_electric", "REVOKE SELECT (body) ON app.notes FROM conf_electric", "body"],
  ] as const) {
    await admin(broken);
    try {
      expect([broken, (await errors()).some((e) => e.includes(says))]).toEqual([broken, true]);
    } finally {
      await admin(mended);
    }
  }
  expect(await errors()).toEqual([]);
  // (unchanged, or applied: the migration was written by the command of its day, whose build may differ)
  expect(rowstile("apply", POLICY)).toMatch(/: (unchanged|applied)$/m);
  expect(rowstile("reapply")).toMatch(/applied again/);
  // a policy whose synced permission is written another way, with a permission more: applied (the index's rows
  // worked out again, and the same), then the policy as it was
  const policy = readFileSync(POLICY, "utf8");
  const changed = policy.replace("  can view = edit or viewer or (folder.view and not {confidential})",
    "  can view = viewer or edit or owner or (folder.view and not {confidential})\n  can rename = edit");
  expect(changed).not.toBe(policy);
  const work = mkdtempSync(join(tmpdir(), "electric-"));
  writeFileSync(join(work, "policy.authz"), changed);
  expect(rowstile("apply", join(work, "policy.authz"))).toMatch(/applied/);
  expect(rowstile("apply", POLICY)).toMatch(/applied/);
  await settled();                                               // after commit: false while changes wait
  const [{ verified }] = (await run("SELECT authz.sync_verify() AS verified")).rows as { verified: boolean }[];
  expect(verified).toBe(true);
  // the shapes go on as they were: a change after the applies arrives, on the same handles, with nothing refetched
  const unshare = "SELECT authz.act_as('user', '5'); SELECT authz.unshare('file', '4', 'viewer', 'user', '1')";
  try {
    await run("SELECT authz.act_as('user', '5'); SELECT authz.share('file', '4', 'viewer', 'user', '1')");
    await live["1"]!.file.holds([1, 2, 3, 4, 6]);
    await asListed();
    expect(Object.fromEntries(USERS.map((u) => [u, live[u]!.file.stream.shapeHandle]))).toEqual(handles);
    for (const u of USERS) {
      expect([u, live[u]!.file.controls.slice(sent[u]).filter((c) => c === "must-refetch")]).toEqual([u, []]);
    }
  } finally {
    await run(unshare);
  }
  await live["1"]!.file.holds([1, 2, 3, 6]);
});

// E13: the notes' body is masked: never in a shape, whatever the client asks; a publication that carries it is
// reported by lint (Electric asks for every column of the old row, so its publication of the notes would)
test("E13: a masked column is never in a shape, even when the client asks for it", async () => {
  await run("ALTER PUBLICATION electric_publication_default ADD TABLE app.notes, authz_sync.note__readers");
  try {
    const lint = (await run("SELECT object || ': ' || problem AS p FROM authz.lint() WHERE severity = 'error'")).rows as { p: string }[];
    expect(lint.map((r) => r.p)).toEqual([expect.stringMatching(/notes.*body: is masked, and the publication electric_publication_default publishes it/)]);
    const notes = new Live("2", "notes");
    try {
      await notes.holds([1]);
      expect(Object.keys(notes.row(1) ?? {}).sort()).toEqual(["author_id", "file_id", "id"]);
      // a change to the note arrives without its body too
      await run("UPDATE app.notes SET body = 'changed', author_id = 1 WHERE id = 1");
      await notes.until((l) => l.row(1)?.author_id === 1, "the note's change");
      expect(Object.keys(notes.row(1) ?? {}).sort()).toEqual(["author_id", "file_id", "id"]);
    } finally {
      notes.close();
    }
    const ask = (query: string) => fetch(`${SERVER}/shapes/notes?offset=-1${query}`, { headers: as("2") });
    for (const columns of ["id,body", '"id","body"', "id, BODY", "id,secret", '"id', "id,,"]) {
      const r = await ask(`&columns=${encodeURIComponent(columns)}`);
      expect([columns, r.status]).toEqual([columns, 400]);
    }
    expect(((await (await ask("&columns=body")).json()) as { detail: string }).detail).toBe("app.notes doesn't sync body: the policy masks it");
    // the columns a client narrows to: the key always with them
    const narrowed = (await (await ask("&columns=file_id")).json()) as { value?: Record<string, string> }[];
    expect(Object.keys(narrowed.find((m) => m.value)?.value ?? {}).sort()).toEqual(["file_id", "id"]);
    // a subset may filter on the synced columns only: Electric keeps it to those the proxy names
    const handle = (await ask("&log=changes_only")).headers.get("electric-handle") ?? "";
    const subset = (where: string) => ask(`&log=changes_only&handle=${handle}&subset__where=${encodeURIComponent(where)}`);
    expect((await subset("file_id = 2")).status).toBe(200);
    expect((await subset("body LIKE 'c%'")).status).toBe(400);
  } finally {
    await run("ALTER PUBLICATION electric_publication_default DROP TABLE app.notes, authz_sync.note__readers");
    await run("UPDATE app.notes SET body = 'bo''s note', author_id = 2 WHERE id = 1");
  }
});

// E14: a user deleted: their keys go, so their shape empties; and the proxy now answers them 401
test("E14: a user deleted: their keys go, and their shape empties", async () => {
  const where = shapes["app.files"].where.user;
  const dee = new Live("4", "files", ELECTRIC, direct("app.files", where, "4"));   // Electric's own, as the proxy set it
  try {
    await dee.holds(await listed("4", "file"));
    await run("DELETE FROM app.team_members WHERE user_id = 4; DELETE FROM app.users WHERE id = 4");
    await dee.holds([]);                                         // (after commit: once the worker has run)
    await live["4"]!.file.holds([]);                            // the proxy's: emptied too, before its next poll is refused
    const keys = (await run("SELECT count(*)::int AS n FROM authz_sync.keys WHERE principal_id = '4'")).rows as { n: number }[];
    expect(keys[0]!.n).toBe(0);
    expect((await fetch(`${SERVER}/shapes/files?offset=-1`, { headers: as("4") })).status).toBe(401);
  } finally {
    dee.close();
  }
});

// E15: a session limited by scopes (a key's, a token's) is refused: the index holds what each principal may read,
// without scopes. A key without scopes signs in as its user; a key that isn't one is 401, in the database's words
test("E15: a session limited by scopes is refused, 403", async () => {
  await settled();                                               // a snapshot, held to the oracle
  const key = async (scopes: string) =>
    ((await asUser<{ k: string }>("2", "SELECT authz.create_api_key('sync', $1) AS k", [scopes]))[0]!).k;
  const scoped = await fetch(`${SERVER}/shapes/files?offset=-1`, { headers: { "x-api-key": await key("read") } });
  expect(scoped.status).toBe(403);
  expect(await scoped.json()).toMatchObject({ type: "https://rowstile.dev/problems/refused", status: 403, code: "AZ704" });
  const whole = await fetch(`${SERVER}/shapes/files?offset=-1`, { headers: { "x-api-key": await key("") } });
  expect(await idsOf(whole)).toEqual(await listed("2", "file"));
  const unknown = await fetch(`${SERVER}/shapes/files?offset=-1`, { headers: { "x-api-key": "ak_nothing" } });
  expect([unknown.status, ((await unknown.json()) as { code: string; detail: string })]).toEqual([401,
    expect.objectContaining({ code: "AZ703", detail: "invalid API key" })]);
});

// E16, keyed by folder alone: a file's readers name its folder's key, which each user holds for every folder they may
// read: a move rewrites no file's readers, only keys, and the shapes follow it as they do the files' readers
test.runIf(MODE === "keyed")("E16: keyed by folder, a folder moved out of reach and back: the files below it leave and return", async () => {
  const readers = async () => ((await run(
    "SELECT md5(string_agg(id || key || xmin, ',' ORDER BY id, key)) AS m FROM authz_sync.file__readers")).rows as { m: string }[])[0]!.m;
  await asListed();
  const before = await readers();
  try {
    await run("UPDATE app.folders SET parent_id = NULL WHERE id = 2");
    await live["2"]!.file.holds([1, 6]);                         // bo read them through eng; file 6 is shared with him
    await live["2"]!.folder.holds([1]);
    await asListed();
  } finally {
    await run("UPDATE app.folders SET parent_id = 1 WHERE id = 2");
  }
  await live["2"]!.file.holds([1, 2, 3, 6]);
  await asListed();
  expect(await readers()).toBe(before);                          // the moves wrote no file's readers
});

// E17, after commit alone: the worker keeps the index, so a change reaches the shapes once it has run. Stopped (a
// deploy, a run that fails), changes wait for it; started again, it works them in
test.runIf(MODE === "after")("E17: after commit, a share arrives once the worker runs, and not before", async () => {
  const unshare = "SELECT authz.act_as('user', '5'); SELECT authz.unshare('file', '4', 'viewer', 'user', '3')";
  await worker!.stop();
  try {
    await run("SELECT authz.act_as('user', '5'); SELECT authz.share('file', '4', 'viewer', 'user', '3')");
    // a write after it, which cy reads: once it has arrived, so has everything committed before it
    await run("UPDATE app.files SET name = 'after the share' WHERE id = 5");
    await live["3"]!.file.until((l) => l.row(5)?.name === "after the share", "the rename");
    expect(live["3"]!.file.ids()).toEqual([5]);                  // the share isn't in the index yet
    const [{ behind }] = (await run("SELECT authz.sync_behind() IS NOT NULL AS behind")).rows as { behind: boolean }[];
    expect(behind).toBe(true);
  } finally {
    worker = syncWorker(OWNER);
  }
  try {
    await live["3"]!.file.holds([4, 5]);
    await asListed();
  } finally {
    await run(unshare);
  }
  await live["3"]!.file.holds([5]);
  await asListed();
});

// the stack's 4: one pooled connection, Ann then Bob: Bob never gets Ann's shape
test("4: a pooled connection carries no one over", async () => {
  await settled();                                               // snapshots, held to the oracle
  for (const user of ["1", "3", "", "5", "3", "1"]) {
    const r = await fetch(`${SERVER_ONE}/shapes/files?offset=-1`, { headers: as(user || null) });
    if (user) expect([user, await idsOf(r)]).toEqual([user, await listed(user, "file")]);
    else expect(r.status).toBe(401);
  }
});

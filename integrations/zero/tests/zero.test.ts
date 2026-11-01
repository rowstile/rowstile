// Zero's conformance suite (a preview): every user's queries of the files, the folders and the notes, live through
// zero-cache and the app's query endpoint, held after each change to what authz.list gives them (the oracle), with
// the ids. test.sh does check 11 (a fresh database: migrate, the policy's tests, the lock file) and 13 (the server
// refuses the owner's connection), and starts the app and zero-cache these checks call.
//
// The checks run whole in each of the index's modes (SYNC_MODE, which test.sh reads): copied in, keyed by folder, and
// after commit, where a worker beside the app runs authz.sync_work() in a loop. The oracle answers at once, and the
// queries follow once the index does: a check waits for what the client holds, whatever the mode. Where it needs the
// index to hold every change made so far before it asks, it waits for the worker's next run first (settled()).
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, expect, test } from "vitest";
import { mutators } from "../src/mutators.js";
import { zql } from "../src/schema.js";
import { syncWorker, type SyncWorker } from "../src/worker.js";
import { ADMIN, APP, Client, MODE, OWNER, POLICY, USERS, listed, owner, run, seed } from "./data.js";

const HERE = join(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(HERE, "..", "..", "core", "cli", "rowstile_cli.py");
const rowstile = (...args: string[]) =>
  execFileSync(process.env.PYTHON ?? "python3", [CLI, ...args], { cwd: HERE, encoding: "utf8", stdio: "pipe" });

const live: Record<string, Client> = {};
/** After commit, the worker, run as the policy's owner: the app role can't call authz.sync_work() */
let worker: SyncWorker | null = null;
/** After commit, once the worker's next run has ended: the index holds every change committed before; else at once. */
const settled = async (): Promise<void> => worker?.ran();

/** Every user's queries hold what authz.list gives them. */
async function asListed(): Promise<void> {
  for (const user of USERS) await live[user]!.listed();
}

beforeAll(async () => {
  await seed();
  if (MODE === "after") worker = syncWorker(OWNER);
  await settled();
  for (const user of USERS) live[user] = new Client(user);
});

afterAll(async () => {
  await worker?.stop();
  for (const c of Object.values(live)) await c.close();
});

// The index in force is in the mode test.sh set up: keyed by folder, the files' readers name their folders' keys;
// after commit, the table of what waits for the worker; copied in, neither
test(`the index is kept in the mode the suite runs in (${MODE})`, async () => {
  const [{ keyed, after }] = (await run(`SELECT
      EXISTS (SELECT 1 FROM authz_sync.file__readers WHERE key LIKE 'folder#%') AS keyed,
      to_regclass('authz_sync.pending') IS NOT NULL AS after`)).rows as { keyed: boolean; after: boolean }[];
  expect({ keyed, after }).toEqual({ keyed: MODE === "keyed", after: MODE === "after" });
});

test("Z1: the first sync of each user's queries is what authz.list gives them", async () => {
  await asListed();
  expect(live["2"]!.rows.file).toEqual([1, 2, 3, 6]);              // bo: through backend, inside eng; and his share
  expect(live["3"]!.rows.folder).toEqual([4]);                     // cy: the ops folder, through ops
});

test("Z2: a share made: the row arrives live; revoked: it leaves", async () => {
  await run("SELECT authz.act_as('user', '5'); SELECT authz.share('file', '4', 'viewer', 'user', '2')");
  await live["2"]!.holds("file", [1, 2, 3, 4, 6]);
  await run("SELECT authz.act_as('user', '5'); SELECT authz.unshare('file', '4', 'viewer', 'user', '2')");
  await live["2"]!.holds("file", [1, 2, 3, 6]);
  await asListed();
});

// Zero syncs the rows a query reads, not only what it returns: the readers and keys it went through. They are the
// user's own: their keys, the readers rows on those keys, and keyed by folder, what each folder they may read gives
// them (given, on their keys) and the folders below it whose keys inherit from it (inherits): never another user's key
test("Z10: what a client holds of the index is its own: its keys, and the readers rows they reach", async () => {
  const bo = live["2"]!;
  const keys = (await bo.zero.run(zql.rowstile_keys)) as readonly { principal_id: string; key: string }[];
  expect(keys.length).toBeGreaterThan(0);
  expect(keys.every((k) => k.principal_id === "2")).toBe(true);
  const held = new Set(keys.map((k) => k.key));
  const reached = new Set(held);
  if (MODE === "keyed") {
    // (the two tables the keyed policy's generated schema has, which the committed one, copied in, hasn't)
    const table = (name: string) => (zql as unknown as Record<string, Parameters<typeof bo.zero.run>[0]>)[name]!;
    const given = (await bo.zero.run(table("rowstile_given"))) as readonly { source: string; key: string }[];
    expect(given.filter((g) => !held.has(g.key))).toEqual([]);
    const sources = new Set(given.map((g) => g.source));
    const inherits = (await bo.zero.run(table("rowstile_inherits"))) as readonly { key: string; source: string }[];
    expect(inherits.filter((i) => !sources.has(i.source))).toEqual([]);
    for (const i of inherits) reached.add(i.key);
  }
  const readers = (await bo.zero.run(zql.rowstile_file_readers)) as readonly { key: string }[];
  expect(readers.length).toBeGreaterThan(0);
  expect(readers.filter((r) => !reached.has(r.key))).toEqual([]);
  expect(readers.filter((r) => /^user:(?!2$)/.test(r.key))).toEqual([]);   // no other user named
});

// Z8 (and the stack's 5): a client that says it is someone else in its own context is sent its token's rows: the
// query endpoint makes the context from the request. (The client runs its local copy of the queries with the
// context it says, so its views show what of its own rows that other principal would read: here, none.)
test("Z8: a client's own context is not believed: its store holds its token's rows, not eve's", async () => {
  const bo = new Client("2", { type: "user", id: "5" });
  try {
    expect(await bo.stored("file", await listed("2", "file"))).toEqual([1, 2, 3, 6]);
    expect(await bo.stored("folder", await listed("2", "folder"))).toEqual([1, 2]);
    expect(await listed("5", "file")).toEqual([4, 5]);              // eve's, which it never gets
  } finally {
    await bo.close();
  }
});

// Z9 (and the stack's 3): nobody signed in: the query endpoint answers 401, which Zero shows as needs-auth, and the
// client gets no row
test("Z9: not signed in: needs-auth, and no row", async () => {
  const nobody = new Client(null);
  try {
    expect(await nobody.state("needs-auth")).toBe("needs-auth");
    expect(nobody.rows).toEqual({ file: [], folder: [], note: [] });
  } finally {
    await nobody.close();
  }
});

test("4: a client signed in as someone the app doesn't know syncs nothing", async () => {
  const stranger = new Client("99");
  try {
    expect(await stranger.state("needs-auth")).toBe("needs-auth");
    expect(stranger.rows.file).toEqual([]);
  } finally {
    await stranger.close();
  }
});


test("Z3: a folder moved out of reach: the files below it leave; moved back: they return", async () => {
  try {
    await run("UPDATE app.folders SET parent_id = NULL WHERE id = 2");
    await live["4"]!.holds("file", [1]);                            // dee read them through eng, given the folder above
    await live["2"]!.holds("file", [1, 6]);                         // bo keeps file 6: it is shared with him too
    await live["4"]!.holds("folder", [1]);
    await asListed();
  } finally {
    await run("UPDATE app.folders SET parent_id = 1 WHERE id = 2");
  }
  await live["4"]!.holds("file", [1, 2, 3, 6]);
  await asListed();
});

test("Z4: a team left: the rows reached only through it leave, and one also reached another way stays", async () => {
  try {
    await run("DELETE FROM app.team_members WHERE team_id = 2 AND user_id = 2");
    await live["2"]!.holds("file", [6]);
    await live["2"]!.holds("folder", []);
    await live["2"]!.holds("note", []);
    await asListed();
  } finally {
    await run("INSERT INTO app.team_members VALUES (2, 2) ON CONFLICT DO NOTHING");
  }
  await live["2"]!.holds("file", [1, 2, 3, 6]);
  await asListed();
});

test("Z5: a sub-team moved under another team: its members' rows follow", async () => {
  try {
    await run("UPDATE app.teams SET parent_id = 3 WHERE id = 2");  // backend, out of eng, into ops
    await live["2"]!.holds("file", [5, 6]);
    await live["2"]!.holds("folder", [4]);
    await live["4"]!.holds("file", [1, 2, 3, 6]);                   // dee is in eng itself
    await asListed();
  } finally {
    await run("UPDATE app.teams SET parent_id = 1 WHERE id = 2");
  }
  await live["2"]!.holds("file", [1, 2, 3, 6]);
  await asListed();
});

test("Z6: a share that ends: the row leaves at the next authz.sync_tick(), and not before", async () => {
  const [{ ends }] = (await run(`SELECT authz.act_as('user', '5');
    SELECT authz.share('file', '4', 'viewer', 'user', '3', '', now() + interval '1 second');
    SELECT expires_at AS ends FROM authz.shares WHERE object_id = '4' AND subject_id = '3'`) as unknown as { rows: { ends: Date }[] }[])[2]!.rows;
  await live["3"]!.holds("file", [4, 5]);
  // the end passes (the database's clock): authz.list no longer gives it, the index still does until the tick
  await run("SELECT pg_sleep_until($1::timestamptz)", [ends]);
  expect(await listed("3", "file")).toEqual([5]);
  await settled();                                               // after commit: the worker ran since, and kept it
  // a write after the end, which cy reads: once it has arrived, so has everything committed before it
  await run("UPDATE app.files SET name = 'after the end' WHERE id = 5");
  await live["3"]!.until(() => live["3"]!.row("file", 5)?.name === "after the end", "the rename");
  expect(live["3"]!.rows.file).toEqual([4, 5]);                  // the stated window: until the tick
  const [{ ticked }] = (await run("SELECT authz.sync_tick() AS ticked")).rows as { ticked: string }[];
  expect(Number(ticked)).toBeGreaterThanOrEqual(1);
  await live["3"]!.holds("file", [5]);                           // after commit: the tick notes it, the worker works it in
  await run("UPDATE app.files SET name = 'e' WHERE id = 5");
  await asListed();
});

test("Z7: confidential set: the file leaves those who saw it only through its folder", async () => {
  try {
    await run("UPDATE app.files SET confidential = true WHERE id = 3");
    await live["2"]!.holds("file", [1, 2, 6]);
    await live["4"]!.holds("file", [1, 2, 6]);
    await live["1"]!.holds("file", [1, 2, 3, 6]);                   // ann may edit it: she still reads it
    await asListed();
  } finally {
    await run("UPDATE app.files SET confidential = false WHERE id = 3");
  }
  await live["2"]!.holds("file", [1, 2, 3, 6]);
  await asListed();
});

// Z11: writes through the app's mutators, on the server in a transaction signed in as the request's user: an allowed
// one arrives in the queries of those who may read it; one the rules refuse comes back to its client as an error,
// in the database's words, and changes nothing
test("Z11: writes through Zero's mutators arrive in the queries; a refused one says why", async () => {
  const ann = live["1"]!.zero;
  const bo = live["2"]!.zero;
  try {
    expect(await ann.mutate(mutators.file.create({ id: 7, folder_id: 2, name: "new" })).server).toEqual({ type: "success" });
    await live["2"]!.holds("file", [1, 2, 3, 6, 7]);
    await live["1"]!.holds("file", [1, 2, 3, 6, 7]);
    expect(await ann.mutate(mutators.file.rename({ id: 7, name: "renamed" })).server).toEqual({ type: "success" });
    await live["2"]!.until(() => live["2"]!.row("file", 7)?.name === "renamed", "file 7 renamed");
    // bo reads file 7, but may not edit it, nor add a file to ann's folder
    const refused = await bo.mutate(mutators.file.rename({ id: 7, name: "bo's" })).server;
    expect(refused).toMatchObject({ type: "error", error: { type: "app" } });
    expect(JSON.stringify(refused)).toMatch(/app\.files/);
    const into = await bo.mutate(mutators.file.create({ id: 8, folder_id: 2, name: "bo's" })).server;
    expect(into).toMatchObject({ type: "error", error: { type: "app" } });
    const [{ name, eight }] = (await run("SELECT (SELECT name FROM app.files WHERE id = 7) AS name, EXISTS (SELECT 1 FROM app.files WHERE id = 8) AS eight"))
      .rows as { name: string; eight: boolean }[];
    expect({ name, eight }).toEqual({ name: "renamed", eight: false });
    await live["2"]!.until(() => live["2"]!.row("file", 7)?.name === "renamed", "file 7 as ann named it");
    await asListed();
  } finally {
    await run("DELETE FROM app.files WHERE id IN (7, 8)");
  }
  await live["2"]!.holds("file", [1, 2, 3, 6]);
});

// Z12: lint finds a Zero role that breaks the rules; applying and applying again leave the clients connected and
// their queries following changes (no reset: no table zero-cache reads changed), and the index agrees with a rebuild
test("Z12: lint, then rowstile apply and reapply leave the queries as they are", async () => {
  const errors = async () => ((await run("SELECT object || ': ' || problem AS p FROM authz.lint() WHERE severity = 'error'"))
    .rows as { p: string }[]).map((r) => r.p);
  expect(await errors()).toEqual([]);
  const admin = (sql: string) => owner((c) => c.query(sql), ADMIN);
  for (const [broken, mended, says] of [
    ["ALTER ROLE conf_zero NOBYPASSRLS", "ALTER ROLE conf_zero BYPASSRLS", "BYPASSRLS"],
    ["GRANT conf_app TO conf_zero", "REVOKE conf_app FROM conf_zero", "one another's members"],
    ["GRANT SELECT (body) ON app.notes TO conf_zero", "REVOKE SELECT (body) ON app.notes FROM conf_zero", "body"],
  ] as const) {
    await admin(broken);
    try {
      expect([broken, (await errors()).some((e) => e.includes(says))]).toEqual([broken, true]);
    } finally {
      await admin(mended);
    }
  }
  expect(await errors()).toEqual([]);
  expect(rowstile("apply", POLICY)).toMatch(/: (unchanged|applied)$/m);
  expect(rowstile("reapply")).toMatch(/applied again/);
  // a policy whose synced permission is written another way, with a permission more: applied, then as it was
  const policy = readFileSync(POLICY, "utf8");
  const changed = policy.replace("  can view = edit or viewer or (folder.view and not {confidential})",
    "  can view = viewer or edit or owner or (folder.view and not {confidential})\n  can rename = edit");
  expect(changed).not.toBe(policy);
  const work = mkdtempSync(join(tmpdir(), "zero-"));
  writeFileSync(join(work, "policy.authz"), changed);
  expect(rowstile("apply", join(work, "policy.authz"))).toMatch(/applied/);
  expect(rowstile("apply", POLICY)).toMatch(/applied/);
  await settled();
  const [{ verified }] = (await run("SELECT authz.sync_verify() AS verified")).rows as { verified: boolean }[];
  expect(verified).toBe(true);
  // the clients go on as they were: still connected, and a change after the applies arrives
  const unshare = "SELECT authz.act_as('user', '5'); SELECT authz.unshare('file', '4', 'viewer', 'user', '1')";
  try {
    await run("SELECT authz.act_as('user', '5'); SELECT authz.share('file', '4', 'viewer', 'user', '1')");
    await live["1"]!.holds("file", [1, 2, 3, 4, 6]);
    await asListed();
    for (const u of USERS) expect([u, live[u]!.zero.connection.state.current.name]).toEqual([u, "connected"]);
  } finally {
    await run(unshare);
  }
  await live["1"]!.holds("file", [1, 2, 3, 6]);
});

// Z13: the notes' body is masked: not in the app's Zero table, nor in zero-cache's publication, so never on a
// client; a publication that would carry it is reported by lint
test("Z13: a masked column is never synced: not in the publication, not on a client", async () => {
  const [{ cols }] = (await run(`SELECT string_agg(a, ',' ORDER BY a) AS cols FROM pg_publication_tables p, unnest(p.attnames) a
    WHERE p.pubname = 'zero_data' AND p.schemaname = 'app' AND p.tablename = 'notes'`)).rows as { cols: string }[];
  expect(cols).toBe("author_id,file_id,id");
  await live["2"]!.holds("note", [1]);
  expect(Object.keys(live["2"]!.row("note", 1) ?? {}).sort()).toEqual(["author_id", "file_id", "id"]);
  // another publication, of every column of the notes: lint says so (it isn't zero-cache's)
  await run("CREATE PUBLICATION zero_masked_check FOR TABLE app.notes");
  try {
    const lint = (await run("SELECT object || ': ' || problem AS p FROM authz.lint() WHERE severity = 'error'")).rows as { p: string }[];
    expect(lint.map((r) => r.p)).toEqual([expect.stringMatching(/notes.*body: is masked, and the publication zero_masked_check publishes it/)]);
  } finally {
    await run("DROP PUBLICATION zero_masked_check");
  }
});

// Z14: a user deleted: their keys go, so their queries empty; and the query endpoint now answers them 401
test("Z14: a user deleted: their keys go, and their queries empty", async () => {
  await live["4"]!.listed();
  await run("DELETE FROM app.team_members WHERE user_id = 4; DELETE FROM app.users WHERE id = 4");
  await live["4"]!.holds("file", []);                            // (after commit: once the worker has run)
  await live["4"]!.holds("folder", []);
  const keys = (await run("SELECT count(*)::int AS n FROM authz_sync.keys WHERE principal_id = '4'")).rows as { n: number }[];
  expect(keys[0]!.n).toBe(0);
  const again = new Client("4");
  try {
    expect(await again.state("needs-auth")).toBe("needs-auth");
  } finally {
    await again.close();
  }
});

// Z15: a session limited by scopes (a key's, a token's) is refused, 403: the index holds what each principal may
// read, without scopes. A key without scopes signs in as its user; a key that isn't one is 401, in the database's
// words
test("Z15: a session limited by scopes is refused, needs-auth; a key without scopes syncs its user's rows", async () => {
  await settled();
  const key = async (scopes: string) => owner(async (c) => {
    await c.query("BEGIN");
    await c.query("SELECT authz.act_as('user', '2')");
    const k = ((await c.query("SELECT authz.create_api_key('sync', $1) AS k", [scopes])).rows[0] as { k: string }).k;
    await c.query("COMMIT");
    return k;
  }, APP);
  for (const token of [`key:${await key("read")}`, "key:ak_nothing"]) {
    const limited = new Client(token);
    try {
      expect([token.slice(0, 8), await limited.state("needs-auth")]).toEqual([token.slice(0, 8), "needs-auth"]);
      expect(limited.rows.file).toEqual([]);
    } finally {
      await limited.close();
    }
  }
  const whole = new Client(`key:${await key("")}`, { type: "user", id: "2" }, "2");
  try {
    await whole.holds("file", await listed("2", "file"));
  } finally {
    await whole.close();
  }
});

// Z16, keyed by folder alone: a file's readers name its folder's key, which no user holds: the index says whose own
// keys it inherits and what each folder gives itself, and the filter joins through them. A move rewrites no file's
// readers and no key, and the queries follow it as they do the files' readers
test.runIf(MODE === "keyed")("Z16: keyed by folder, a folder moved out of reach and back: the files below it leave and return", async () => {
  const md5 = async (sql: string) => ((await run(`SELECT md5(string_agg(x, ',' ORDER BY x)) AS m FROM (${sql}) z(x)`)).rows as { m: string }[])[0]!.m;
  const readers = () => md5("SELECT id || key || xmin FROM authz_sync.file__readers UNION ALL SELECT principal_id || key || xmin FROM authz_sync.keys");
  expect(await md5("SELECT key FROM authz_sync.keys WHERE key LIKE 'folder#%'")).toBeNull();
  await asListed();
  const before = await readers();
  try {
    await run("UPDATE app.folders SET parent_id = NULL WHERE id = 2");
    await live["2"]!.holds("file", [1, 6]);
    await live["2"]!.holds("folder", [1]);
    await asListed();
  } finally {
    await run("UPDATE app.folders SET parent_id = 1 WHERE id = 2");
  }
  await live["2"]!.holds("file", [1, 2, 3, 6]);
  await asListed();
  expect(await readers()).toBe(before);
});

// Z17, after commit alone: the worker keeps the index, so a change reaches the queries once it has run
test.runIf(MODE === "after")("Z17: after commit, a share arrives once the worker runs, and not before", async () => {
  const unshare = "SELECT authz.act_as('user', '5'); SELECT authz.unshare('file', '4', 'viewer', 'user', '3')";
  await worker!.stop();
  try {
    await run("SELECT authz.act_as('user', '5'); SELECT authz.share('file', '4', 'viewer', 'user', '3')");
    await run("UPDATE app.files SET name = 'after the share' WHERE id = 5");
    await live["3"]!.until(() => live["3"]!.row("file", 5)?.name === "after the share", "the rename");
    expect(live["3"]!.rows.file).toEqual([5]);
    const [{ behind }] = (await run("SELECT authz.sync_behind() IS NOT NULL AS behind")).rows as { behind: boolean }[];
    expect(behind).toBe(true);
  } finally {
    worker = syncWorker(OWNER);
  }
  try {
    await live["3"]!.holds("file", [4, 5]);
    await asListed();
  } finally {
    await run(unshare);
  }
  await live["3"]!.holds("file", [5]);
  await asListed();
});

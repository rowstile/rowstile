// PowerSync's conformance suite (a preview): every user's files, folders and notes, live through the PowerSync service
// from the policy's mirrors (a bucket for each key the user holds), held after each change to what authz.list gives
// them (the oracle), with the ids. test.sh does check 11 (a fresh database: migrate, the policy's tests, the lock file)
// and 13 (the server refuses the owner's connection), and starts the app and the service these checks call.
//
// The checks run whole in each of the index's modes PowerSync takes (SYNC_MODE, which test.sh reads): copied in, and
// after commit, where a worker beside the app runs authz.sync_work() in a loop (a mirrored line can't be keyed by
// folder: AZ811). Where a check needs the index to hold every change made so far, it waits for the worker first.
import { execFileSync } from "node:child_process";
import { createHmac } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, expect, test } from "vitest";
import { syncWorker, type SyncWorker } from "../src/worker.js";
import { ADMIN, APP, Client, MODE, OWNER, POLICY, SERVER, SERVER_ONE, SERVICE, USERS, listed, owner, run, seed, type Kind } from "./data.js";

const HERE = join(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(HERE, "..", "..", "core", "cli", "rowstile_cli.py");
const rowstile = (...args: string[]) =>
  execFileSync(process.env.PYTHON ?? "python3", [CLI, ...args], { cwd: HERE, encoding: "utf8", stdio: "pipe" });
const live: Record<string, Client> = {};
/** After commit, the worker, run as the policy's owner: the app role can't call authz.sync_work() */
let worker: SyncWorker | null = null;
/** After commit, once the worker's next run has ended: the index holds every change committed before; else at once. */
const settled = async (): Promise<void> => worker?.ran();

/** The users deleted (P14): their tables are held to nothing more. */
const gone = new Set<string>();
let barriers = 0;
/** Every user's tables hold what authz.list gives them, once each client has had every change committed so far: a
 *  rename of one of its rows, all in one transaction after the changes, arrives after them (a client applies a
 *  checkpoint of all its buckets at once). A client that holds no file nor folder has none to rename: it is held to
 *  what it holds when asked. */
async function asListed(): Promise<void> {
  await settled();                                               // after commit: the index has the changes first
  const want: { user: string; ids: Record<Kind, number[]> }[] = [];
  for (const user of USERS.filter((u) => !gone.has(u))) {
    const ids = { file: await listed(user, "file"), folder: await listed(user, "folder"), note: await listed(user, "note") };
    want.push({ user, ids });
  }
  const mark = ` #${++barriers}`;
  const barrier = want.map((w) => w.ids.file.length ? ["file", w.ids.file[0]!] as const
    : w.ids.folder.length ? ["folder", w.ids.folder[0]!] as const : null);
  const ids = (kind: Kind) => [...new Set(barrier.flatMap((r) => (r?.[0] === kind ? [r[1]] : [])))];
  await run(`WITH files AS (UPDATE app.files SET name = regexp_replace(name, ' #[0-9]+$', '') || $1 WHERE id = ANY($2::int[]))
    UPDATE app.folders SET name = regexp_replace(name, ' #[0-9]+$', '') || $1 WHERE id = ANY($3::int[])`,
    [mark, ids("file"), ids("folder")]);
  for (const [i, w] of want.entries()) {
    if (barrier[i]) {
      const [kind, renamed] = barrier[i]!;
      await live[w.user]!.until(async () => String((await live[w.user]!.row(kind, renamed))?.name).endsWith(mark),
        `${kind} ${renamed} renamed after the changes`);
    }
    for (const kind of Object.keys(w.ids) as Kind[]) await live[w.user]!.holds(kind, w.ids[kind]);
  }
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

test(`the index is kept in the mode the suite runs in (${MODE}), with a mirror of each synced table`, async () => {
  const [{ after, mirrors }] = (await run(`SELECT to_regclass('authz_sync.pending') IS NOT NULL AS after,
      (SELECT count(*)::int FROM pg_class WHERE relnamespace = 'authz_sync'::regnamespace AND relname LIKE '%\\_\\_mirror') AS mirrors`))
    .rows as { after: boolean; mirrors: number }[];
  expect({ after, mirrors }).toEqual({ after: MODE === "after", mirrors: 3 });
});

test("P1: the first sync of each user's tables is what authz.list gives them", async () => {
  await asListed();
  expect(await live["2"]!.ids("file")).toEqual([1, 2, 3, 6]);       // bo: through backend, inside eng; and his share
  expect(await live["3"]!.ids("folder")).toEqual([4]);              // cy: the ops folder, through ops
});

test("P2: a share made: the row arrives live; revoked: it leaves", async () => {
  const unshare = "SELECT authz.act_as('user', '5'); SELECT authz.unshare('file', '4', 'viewer', 'user', '2')";
  try {
    await run("SELECT authz.act_as('user', '5'); SELECT authz.share('file', '4', 'viewer', 'user', '2')");
    await live["2"]!.holds("file", [1, 2, 3, 4, 6]);
    await run(unshare);
    await live["2"]!.holds("file", [1, 2, 3, 6]);
    await asListed();
  } finally {
    await run(unshare);
  }
});

test("P3: a folder moved out of reach: the files below it leave; moved back: they return", async () => {
  try {
    await run("UPDATE app.folders SET parent_id = NULL WHERE id = 2");
    await live["4"]!.holds("file", [1]);
    await live["2"]!.holds("file", [1, 6]);
    await live["4"]!.holds("folder", [1]);
    await asListed();
  } finally {
    await run("UPDATE app.folders SET parent_id = 1 WHERE id = 2");
  }
  await live["4"]!.holds("file", [1, 2, 3, 6]);
  await asListed();
});

test("P4: a team left: the rows reached only through it leave, and one also reached another way stays", async () => {
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

test("P5: a sub-team moved under another team: its members' rows follow", async () => {
  try {
    await run("UPDATE app.teams SET parent_id = 3 WHERE id = 2");
    await live["2"]!.holds("file", [5, 6]);
    await live["2"]!.holds("folder", [4]);
    await live["4"]!.holds("file", [1, 2, 3, 6]);
    await asListed();
  } finally {
    await run("UPDATE app.teams SET parent_id = 1 WHERE id = 2");
  }
  await live["2"]!.holds("file", [1, 2, 3, 6]);
  await asListed();
});

test("P6: a share that ends: the row leaves at the next authz.sync_tick(), and not before", async () => {
  const [{ ends }] = (await run(`SELECT authz.act_as('user', '5');
    SELECT authz.share('file', '4', 'viewer', 'user', '3', '', now() + interval '1 second');
    SELECT expires_at AS ends FROM authz.shares WHERE object_id = '4' AND subject_id = '3'`) as unknown as { rows: { ends: Date }[] }[])[2]!.rows;
  await live["3"]!.holds("file", [4, 5]);
  await run("SELECT pg_sleep_until($1::timestamptz)", [ends]);
  expect(await listed("3", "file")).toEqual([5]);
  await settled();
  // a write after the end, which cy reads: once it has arrived, so has everything committed before it
  await run("UPDATE app.files SET name = 'after the end' WHERE id = 5");
  await live["3"]!.until(async () => (await live["3"]!.row("file", 5))?.name === "after the end", "the rename");
  expect(await live["3"]!.ids("file")).toEqual([4, 5]);           // the stated window: until the tick
  const [{ ticked }] = (await run("SELECT authz.sync_tick() AS ticked")).rows as { ticked: string }[];
  expect(Number(ticked)).toBeGreaterThanOrEqual(1);
  await live["3"]!.holds("file", [5]);
  await run("UPDATE app.files SET name = 'e' WHERE id = 5");
  await asListed();
});

test("P7: confidential set: the file leaves those who saw it only through its folder", async () => {
  try {
    await run("UPDATE app.files SET confidential = true WHERE id = 3");
    await live["2"]!.holds("file", [1, 2, 6]);
    await live["4"]!.holds("file", [1, 2, 6]);
    await live["1"]!.holds("file", [1, 2, 3, 6]);
    await asListed();
  } finally {
    await run("UPDATE app.files SET confidential = false WHERE id = 3");
  }
  await live["2"]!.holds("file", [1, 2, 3, 6]);
  await asListed();
});

// P8: the service checks the token, which only the app signs: the app's own is taken, and the same signed with another
// key is refused. The app's lasts five minutes: the service believes it until then
test("P8: a token the app didn't sign is refused by the service", async () => {
  const given = (await (await fetch(`${SERVER}/api/powersync/token`, { method: "POST", headers: { "x-user": "1" } })).json()) as { token: string };
  const [head, body] = given.token.split(".") as [string, string, string];
  const claims = JSON.parse(Buffer.from(body, "base64url").toString()) as { sub: string; iat: number; exp: number };
  expect([claims.sub, claims.exp - claims.iat]).toEqual(["1", 300]);
  const forged = `${head}.${body}.${createHmac("sha256", "another key").update(`${head}.${body}`).digest("base64url")}`;
  /** The service's answer to a sync request with the token (the stream itself left unread). */
  const stream = async (token: string) => {
    const stop = new AbortController();
    const r = await fetch(`${SERVICE}/sync/stream`, { method: "POST", signal: stop.signal,
      headers: { authorization: `Token ${token}`, "content-type": "application/json" }, body: JSON.stringify({ raw_data: true }) });
    stop.abort();
    return r.status;
  };
  expect(await stream(given.token)).toBe(200);
  expect(await stream(forged)).toBe(401);
});

// P9 (and the stack's 3): nobody signed in: the app gives no token, and the client gets no row
test("P9: not signed in: no token, and no row", async () => {
  const nobody = new Client(null);
  try {
    await nobody.until(async () => nobody.asked.includes(401), "the app's 401");
    expect(await nobody.ids("file")).toEqual([]);
  } finally {
    await nobody.close();
  }
});

// P10: what the client is synced of a row is the stream's columns: never the readers (who else reads it), nor the
// masked body of a note (the mirror hasn't it); and its buckets are its keys
test("P10: the client is synced no readers, and no masked column", async () => {
  await live["2"]!.holds("note", [1]);
  const synced = await live["2"]!.synced();
  expect(synced.length).toBeGreaterThan(0);
  expect(synced.filter((r) => "readers" in r.data)).toEqual([]);
  expect(synced.filter((r) => r.type === "notes" && "body" in r.data)).toEqual([]);
  // ... in buckets keyed by the keys bo holds (those that hold rows, for each stream): never one for each row
  const keys = new Set(((await run("SELECT key FROM authz_sync.keys WHERE principal_type = 'user' AND principal_id = '2'")).rows as { key: string }[])
    .map((r) => r.key));
  const buckets = ((await live["2"]!.db.getAll("SELECT name FROM ps_buckets WHERE name <> '$local'")) as { name: string }[]).map((r) => r.name);
  const by = buckets.map((b) => (JSON.parse(b.slice(b.indexOf("["))) as string[])[0]!);
  expect(by.length).toBeGreaterThan(0);
  expect(by.filter((k) => !keys.has(k))).toEqual([]);
});

// P11: writes through the app arrive in the streams; a client's own write that the rules refuse is the app's 403,
// in the database's words, and its upload queue moves on
test("P11: writes through the app arrive; a refused one from a client's queue says why", async () => {
  try {
    const post = await fetch(`${SERVER}/api/files`, { method: "POST", headers: { "x-user": "1", "content-type": "application/json" },
      body: JSON.stringify({ id: 7, folder_id: 2, name: "new" }) });
    expect(post.status).toBe(201);
    await live["2"]!.holds("file", [1, 2, 3, 6, 7]);
    // ann renames file 7 in her client: its queue sends it to the app, as her, and every client gets it
    await live["1"]!.holds("file", [1, 2, 3, 6, 7]);
    await live["1"]!.db.execute("UPDATE files SET name = 'renamed' WHERE id = '7'");
    await live["2"]!.until(async () => (await live["2"]!.row("file", 7))?.name === "renamed", "file 7 renamed");
    // bo renames it in his: the app refuses it (he reads file 7, but may not edit it)
    await live["2"]!.db.execute("UPDATE files SET name = 'bo''s' WHERE id = '7'");
    await live["2"]!.until(async () => live["2"]!.refused.length > 0, "the refusal");
    expect(live["2"]!.refused[0]).toMatch(/^403 .*AZ709/);
    const [{ name }] = (await run("SELECT name FROM app.files WHERE id = 7")).rows as { name: string }[];
    expect(name).toBe("renamed");
    await asListed();
  } finally {
    await run("DELETE FROM app.files WHERE id = 7");
  }
  await live["2"]!.holds("file", [1, 2, 3, 6]);
});

// P12: lint finds a PowerSync role that breaks the rules; applying, applying again and a changed policy leave the
// clients syncing (the mirrors kept), and the index agrees with a rebuild, the mirrors with their tables
test("P12: lint, then rowstile apply and reapply leave the clients syncing", async () => {
  const errors = async () => ((await run("SELECT object || ': ' || problem AS p FROM authz.lint() WHERE severity = 'error'"))
    .rows as { p: string }[]).map((r) => r.p);
  expect(await errors()).toEqual([]);
  const admin = (sql: string) => owner((c) => c.query(sql), ADMIN);
  for (const [broken, mended, says] of [
    ["ALTER ROLE conf_ps NOBYPASSRLS", "ALTER ROLE conf_ps BYPASSRLS", "BYPASSRLS"],
    ["GRANT conf_app TO conf_ps", "REVOKE conf_app FROM conf_ps", "one another's members"],
  ] as const) {
    await admin(broken);
    try {
      expect([broken, (await errors()).some((e) => e.includes(says))]).toEqual([broken, true]);
    } finally {
      await admin(mended);
    }
  }
  expect(await errors()).toEqual([]);
  const mirror = async () => ((await run("SELECT 'authz_sync.file__mirror'::regclass::oid::int AS o")).rows as { o: number }[])[0]!.o;
  const kept = await mirror();
  expect(rowstile("apply", POLICY)).toMatch(/: (unchanged|applied)$/m);
  expect(rowstile("reapply")).toMatch(/applied again/);
  const policy = readFileSync(POLICY, "utf8");
  const changed = policy.replace("  can view = edit or viewer or (folder.view and not {confidential})",
    "  can view = viewer or edit or owner or (folder.view and not {confidential})\n  can rename = edit");
  expect(changed).not.toBe(policy);
  const work = mkdtempSync(join(tmpdir(), "powersync-"));
  writeFileSync(join(work, "policy.authz"), changed);
  expect(rowstile("apply", join(work, "policy.authz"))).toMatch(/applied/);
  expect(rowstile("apply", POLICY)).toMatch(/applied/);
  expect(await mirror()).toBe(kept);                               // the service reads the same table
  await settled();
  const [{ verified }] = (await run("SELECT authz.sync_verify() AS verified")).rows as { verified: boolean }[];
  expect(verified).toBe(true);
  const unshare = "SELECT authz.act_as('user', '5'); SELECT authz.unshare('file', '4', 'viewer', 'user', '1')";
  try {
    await run("SELECT authz.act_as('user', '5'); SELECT authz.share('file', '4', 'viewer', 'user', '1')");
    await live["1"]!.holds("file", [1, 2, 3, 4, 6]);
    await asListed();
  } finally {
    await run(unshare);
  }
  await live["1"]!.holds("file", [1, 2, 3, 6]);
});

// P14: a user deleted: their keys go, so their buckets empty; and the app gives them no token
test("P14: a user deleted: their keys go, and their tables empty", async () => {
  await live["4"]!.listed();
  await run("DELETE FROM app.team_members WHERE user_id = 4; DELETE FROM app.users WHERE id = 4");
  gone.add("4");                                                 // held to nothing more from now on
  await live["4"]!.holds("file", []);
  await live["4"]!.holds("folder", []);
  const keys = (await run("SELECT count(*)::int AS n FROM authz_sync.keys WHERE principal_id = '4'")).rows as { n: number }[];
  expect(keys[0]!.n).toBe(0);
  expect((await fetch(`${SERVER}/api/powersync/token`, { method: "POST", headers: { "x-user": "4" } })).status).toBe(401);
});

// P15: a session limited by scopes (a key's, a token's) gets no token, 403: the index holds what each principal may
// read, without scopes. A key without scopes syncs its user's rows
test("P15: a session limited by scopes gets no token; a key without scopes syncs its user's rows", async () => {
  await settled();
  const key = async (scopes: string) => owner(async (c) => {
    await c.query("BEGIN");
    await c.query("SELECT authz.act_as('user', '2')");
    const k = ((await c.query("SELECT authz.create_api_key('sync', $1) AS k", [scopes])).rows[0] as { k: string }).k;
    await c.query("COMMIT");
    return k;
  }, APP);
  const scoped = await fetch(`${SERVER}/api/powersync/token`, { method: "POST", headers: { "x-api-key": await key("read") } });
  expect(scoped.status).toBe(403);
  const unknown = await fetch(`${SERVER}/api/powersync/token`, { method: "POST", headers: { "x-api-key": "ak_nothing" } });
  expect([unknown.status, ((await unknown.json()) as { code: string }).code]).toEqual([401, "AZ703"]);
  const whole = new Client("2", await key(""));
  const unshare = "SELECT authz.act_as('user', '5'); SELECT authz.unshare('file', '4', 'viewer', 'user', '2')";
  try {
    await whole.holds("file", await listed("2", "file"));
    // the key revoked: the app gives it no token now, but the service believes the one it gave until it ends, so
    // the client goes on syncing until then (five minutes)
    await run(`SELECT authz.act_as('user', '2');
      SELECT authz.revoke_api_key((SELECT max(id) FROM authz.api_keys WHERE user_id = '2' AND scopes = ''))`);
    const again = await fetch(`${SERVER}/api/powersync/token`, { method: "POST", headers: { "x-api-key": whole.key! } });
    expect([again.status, ((await again.json()) as { code: string }).code]).toEqual([401, "AZ703"]);
    await run("SELECT authz.act_as('user', '5'); SELECT authz.share('file', '4', 'viewer', 'user', '2')");
    await whole.holds("file", [1, 2, 3, 4, 6]);
  } finally {
    await whole.close();
    await run(unshare);
  }
});

// P17, after commit alone: the worker keeps the index (and so the mirrors), so a change reaches the clients once it
// has run
test.runIf(MODE === "after")("P17: after commit, a share arrives once the worker runs, and not before", async () => {
  const unshare = "SELECT authz.act_as('user', '5'); SELECT authz.unshare('file', '4', 'viewer', 'user', '3')";
  await worker!.stop();
  try {
    await run("SELECT authz.act_as('user', '5'); SELECT authz.share('file', '4', 'viewer', 'user', '3')");
    await run("UPDATE app.files SET name = 'after the share' WHERE id = 5");
    await live["3"]!.until(async () => (await live["3"]!.row("file", 5))?.name === "after the share", "the rename");
    expect(await live["3"]!.ids("file")).toEqual([5]);
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
  await run("UPDATE app.files SET name = 'e' WHERE id = 5");
  await asListed();
});

// the stack's 4: the app with a pool of one connection, asked for tokens and sent writes as one user, then nobody,
// then another: each token names whoever asked, and each write is judged as theirs
test("4: a pooled connection carries no one over", async () => {
  const sub = async (r: Response) =>
    (JSON.parse(Buffer.from(((await r.json()) as { token: string }).token.split(".")[1]!, "base64url").toString()) as { sub: string }).sub;
  for (const user of ["1", "3", null, "5", "3", "1"]) {
    const r = await fetch(`${SERVER_ONE}/api/powersync/token`, { method: "POST", headers: user === null ? {} : { "x-user": user } });
    if (user === null) expect(r.status).toBe(401);
    else expect([user, await sub(r)]).toEqual([user, user]);
  }
  const rename = (user: string, name: string) => fetch(`${SERVER_ONE}/api/files/1`,
    { method: "PATCH", headers: { "x-user": user, "content-type": "application/json" }, body: JSON.stringify({ name }) });
  try {
    expect((await rename("1", "pooled")).status).toBe(200);
    const refused = await rename("2", "bo's");                     // bo reads file 1, but may not edit it
    expect([refused.status, ((await refused.json()) as { code: string }).code]).toEqual([403, "AZ709"]);
    expect((await rename("1", "pooled again")).status).toBe(200);
    const [{ name }] = (await run("SELECT name FROM app.files WHERE id = 1")).rows as { name: string }[];
    expect(name).toBe("pooled again");
  } finally {
    await run("UPDATE app.files SET name = 'a' WHERE id = 1");
  }
  await asListed();
});

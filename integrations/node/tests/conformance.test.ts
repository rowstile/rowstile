// The conformance suite (integrations/README.md): the same checks for every stack. This is a plain Node server,
// Express 5 on node-postgres, Drizzle and postgres.js, with Drizzle Kit's migrations; its tests run on Jest.
// test.sh does check 11 (a fresh database: migrate, the policy's tests, then Drizzle Kit's own diff) and 13 (the
// server refuses the owner's connection), and starts the servers these checks call, before they run.
import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeEach, describe, expect, test } from "@jest/globals";
import express from "express";
import pg from "pg";
import { drizzle } from "drizzle-orm/node-postgres";
import { eq, sql as sqlTag } from "drizzle-orm";
import { actingAs, ConnectionProblem, current, errorCode, NotSignedIn, principal, sqlstate, translate } from "@rowstile/client";
import { databasePerWorker } from "@rowstile/jest";
import { expect as drizzleExpect, inIds, withAuthz } from "@rowstile/drizzle";
import { authz } from "@rowstile/pg";
import { problems } from "../src/app.js";
import { db, pgjs, pool, sql } from "../src/db.js";
import { digest } from "../src/jobs.js";
import { notes, projects } from "../src/schema.js";
import { APP, EXPECTED, OWNER, SERVER, SERVER_ONE, TESTS, appAt, as, json, owner, seed } from "./data.js";

const HERE = join(dirname(fileURLToPath(import.meta.url)), "..", "..");     // integrations/node (from build/tests)
const ROOT = join(HERE, "..", "..");
const CLI = join(ROOT, "core", "cli", "rowstile_cli.py");
const PYTHON = process.env.PYTHON ?? "python3";
// the tools' own scripts, run with this Node
const TOOL: Record<string, string> = {
  tsc: join(ROOT, "node_modules", "typescript", "bin", "tsc"),
  "drizzle-kit": join(ROOT, "node_modules", "drizzle-kit", "bin.cjs"),
};
const run = (tool: string, args: string[], cwd: string) =>
  spawnSync(process.execPath, [TOOL[tool] ?? tool, ...args], { cwd, encoding: "utf8", env: process.env });
const ids = async (r: Response) => (await r.json()) as unknown;

beforeEach(() => seed());
afterAll(async () => {
  await pool.end();
  await pgjs.sql.end();
});

// 1, 2: a list shows only the user's rows; signed out on purpose, only what anyone may see
test("1, 2: lists show what each may see", async () => {
  for (const [user, want] of Object.entries(EXPECTED)) {
    expect([user, await ids(await fetch(`${SERVER}/api/notes`, as(user || null)))]).toEqual([user, want]);
  }
  expect(await ids(await fetch(`${SERVER}/api/projects`))).toEqual([3]);        // node-postgres
  expect(await ids(await fetch(`${SERVER}/api/pgjs/projects`, as("2")))).toEqual([2, 3]);   // postgres.js
});

// 3: not signed in at all: the not-signed-in error (AZ701), naming act_as
test("3: not signed in is an error that says how", async () => {
  const e = await owner(async (c) => {
    await c.query("BEGIN");
    return c.query("SELECT count(*) FROM app.notes").catch((err: unknown) => err);
  }, APP) as { code?: string; hint?: string };
  expect([e.code, e.hint]).toEqual(["28000", expect.stringContaining("act_as")]);
  expect(translate(e)).toBeInstanceOf(NotSignedIn);
  expect(errorCode(e)).toBe("AZ701");                 // rowstile help AZ701
  // a Drizzle query outside a signed-in transaction
  const outside = await drizzle(pool).select().from(notes).catch((err: unknown) => err);
  expect(translate(outside)).toBeInstanceOf(NotSignedIn);
});

// 4: one pooled connection, Ann then Bob: Bob never sees Ann's rows
test("4: a pooled connection carries no one over", async () => {
  for (const user of ["1", "2", "", "3", "2"]) {
    expect([user, await ids(await fetch(`${SERVER_ONE}/api/notes`, as(user || null)))]).toEqual([user, EXPECTED[user]]);
  }
});

// 5: concurrent requests never mix users; nor do the app's own calls, side by side
test("5: concurrent requests never mix users", async () => {
  const users = Array.from({ length: 40 }, (_, i) => ["1", "2", "3", ""][i % 4] ?? "");
  const got = await Promise.all(users.map((u) => fetch(`${SERVER}/api/notes`, as(u || null)).then(ids)));
  expect(got).toEqual(users.map((u) => EXPECTED[u]));
  const one = await Promise.all(users.map((u) => fetch(`${SERVER_ONE}/api/projects`, as(u || null)).then(ids)));
  expect(one).toEqual(users.map((u) => ({ "1": [1, 3], "2": [2, 3], "3": [1, 3], "": [3] })[u]));
  const listed = await Promise.all(users.map((u) => actingAs(u || null, () => db.list("note", "view"))));
  expect(listed).toEqual(users.map((u) => EXPECTED[u]?.map(String)));
});

// 6: a refused insert: 403, with the problem body naming the rule
test("6: a refused insert says which rule", async () => {
  const r = await fetch(`${SERVER}/api/notes`, as("2", json("POST", { project_id: 3, body: "hi" })));
  expect(r.status).toBe(403);
  expect(r.headers.get("content-type")).toMatch(/^application\/problem\+json/);
  const body = await r.json() as { table: string; command: string; detail: string; why: string[]; code: string };
  expect([body.table, body.command, body.code]).toEqual(["app.notes", "insert", "AZ709"]);
  expect(body.detail).toContain("user 2 may not insert this row into app.notes");
  expect(body.why.some((line) => line.includes("project.edit"))).toBe(true);
});

// 7: an update of a hidden row: 404; of a visible row the user may not edit: 403, with the reason
test("7: hidden is 404, not allowed is 403", async () => {
  const patch = (id: number, user: string) => fetch(`${SERVER}/api/notes/${id}`, as(user, json("PATCH", { body: "x" })));
  const hidden = await patch(1, "2");
  const refused = await patch(1, "3");
  const mine = await patch(4, "3");
  const gone = await fetch(`${SERVER}/api/notes/2`, as("1", { method: "DELETE" }));
  const no = await fetch(`${SERVER}/api/notes/1`, as("3", { method: "DELETE" }));
  expect([hidden.status, await hidden.json()]).toEqual([404, {
    type: "https://rowstile.dev/problems/not-found", title: "Not Found", status: 404, detail: "app.notes 1 not found" }]);
  expect(refused.status).toBe(403);
  const why = await refused.json() as { command: string; code: string; why: string[]; detail: string };
  expect([why.command, why.code]).toEqual(["update", "AZ709"]);       // rowstile help AZ709
  expect(why.why.some((line) => line.includes("edit"))).toBe(true);
  // worded as the database words a refused insert: who, the command, the row, the table
  expect(why.detail).toBe("permission denied: user 3 may not update row 1 of app.notes");
  expect([mine.status, gone.status, no.status]).toEqual([200, 404, 403]);
  expect((await no.json() as { detail: string }).detail).toBe("permission denied: user 3 may not delete row 1 of app.notes");
  // in the app's own code, as the matchers say it
  await expect(actingAs("3", () => db.transaction(async (tx) => drizzleExpect(tx,
    await tx.update(notes).set({ body: "x" }).where(eq(notes.id, 1)).returning(), "app.notes", "update", 1))))
    .rejects.toBeRefused("update", "note.edit");
  await expect(actingAs("2", () => sql.transaction(async (c) =>
    sql.expect(await c.query("DELETE FROM app.notes WHERE id = 1"), "app.notes", "delete", 1)))).rejects.toBeNotFound();
});

// 8: an insert read back works when the select rule allows it, and is explained when not
test("8: insert, then read back", async () => {
  const post = (path: string, user: string, body: object) => fetch(`${SERVER}${path}`, as(user, json("POST", body)));
  const ok = await post("/api/notes", "1", { project_id: 1, body: "new" });
  const unreadable = await post("/api/inbox", "1", { recipient_id: 2, body: "hi bo" });
  const quiet = await post("/api/inbox/quietly", "1", { recipient_id: 2, body: "hi bo" });
  expect(ok.status).toBe(201);
  expect((await ok.json() as { id: number }).id).toBeGreaterThan(100);
  expect(unreadable.status).toBe(403);
  const why = await unreadable.json() as { command: string; table: string; detail: string };
  expect([why.command, why.table]).toEqual(["select", "inbox"]);     // Postgres names no schema for it, nor does pg
  expect(why.detail).toContain("may not see the row as written");
  expect(quiet.status).toBe(202);
  expect(await ids(await fetch(`${SERVER}/api/inbox`, as("2")))).toHaveLength(1);   // bo reads it
});

// 9: the generated names type-check, and a wrong permission name doesn't: in the generated client, and in the
// SDK's own calls
test("9: the generated names type-check", () => {
  execFileSync(PYTHON, [CLI, "client"], { cwd: HERE, stdio: "pipe" });
  const dir = join(HERE, ".work", "typecheck");
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const tsconfig = (file: string) => JSON.stringify({ extends: "../../tsconfig.json", compilerOptions: { noEmit: true },
    include: [file, "../../src/authz.gen.ts"], exclude: [] });
  const use = (perm: string) => `import { sql } from "../../src/db.js";\nimport type { Permission } from "@rowstile/client";\n` +
    `export const ok = sql.can("note", 1, "${perm}");\nexport const p: Permission<"project"> = "view";\n`;
  const check = (name: string, perm: string) => {
    writeFileSync(join(dir, `${name}.ts`), use(perm));
    writeFileSync(join(dir, `tsconfig.${name}.json`), tsconfig(`${name}.ts`));
    return run("tsc", ["-p", `tsconfig.${name}.json`], dir);
  };
  const good = check("good", "edit");
  const bad = check("bad", "edt");
  expect([good.status, good.stdout + good.stderr]).toEqual([0, ""]);
  expect(bad.status).not.toBe(0);
  expect(bad.stdout).toContain('"edt"');
});

// 10: a background job signs in as a service principal
test("10: a job acts for its service", async () => {
  const { count, who } = await actingAs("3", () => digest());      // whatever started it
  expect(who).toEqual({ type: "service", id: "1" });
  expect(count).toBe(2);                                            // project 1 (it is added to) and the public one
  // ... and only when the code names it: an id is a user's, whatever it holds (ids come from outside)
  expect(principal("service:1")).toEqual({ type: "user", id: "service:1" });
  expect(await actingAs(["service", 1], () => db.list("project", "view"))).toEqual(["1", "3"]);
});

// A transaction is one principal's (a sign-in lasts the database transaction): inside ann's, the same object's work for
// a service or for nobody throws before anything is sent for it; the transaction goes on as ann's, and commits
test("a transaction is one principal's: another's work inside it is refused", async () => {
  const said = (who: string) => "this transaction is signed in as user 1 already, and a sign-in lasts the database " +
    `transaction: ${who}'s work can't run inside it. Run it after, or in a transaction of its own (another connection)`;
  const refused = (work: () => Promise<unknown>) => work().then(() => "it ran", (e: Error) => e.message);
  const ME = "SELECT current_setting('authz.user_id') AS x";
  const ran: string[] = [];
  const seen = await actingAs("1", () => db.transaction(async (tx) => [
    await refused(() => actingAs(["service", 1], () => db.list("project", "view"))),
    await refused(() => db.transaction(async () => ran.push("drizzle"), null)),
    ((await tx.execute(sqlTag.raw(ME))).rows[0] as { x: string }).x,
    (await tx.update(notes).set({ body: "still ann's" }).where(eq(notes.id, 1)).returning({ id: notes.id }))[0].id,
  ]));
  expect(seen).toEqual([said("service 1"), said("nobody"), "1", 1]);
  expect(await actingAs("1", () => sql.transaction(async (c) => [
    await refused(() => sql.transaction(async () => ran.push("pg"), "2")),
    (await c.query(ME)).rows[0].x,
  ]))).toEqual([said("user 2"), "1"]);
  expect(await actingAs("1", () => pgjs.begin(async (tx) => [
    await refused(() => actingAs("2", () => pgjs.can("project", 2, "edit"))),
    (await tx.unsafe(ME))[0].x,
  ]))).toEqual([said("user 2"), "1"]);
  expect(ran).toEqual([]);
  expect((await actingAs("1", () => sql.query("SELECT body FROM app.notes WHERE id = 1"))).rows).toEqual([{ body: "still ann's" }]);
});

// 12: the framework's test database has the policy: a copy of the migrated one for each Jest worker (this file's,
// and tests/package.test.ts's: test.sh counts them)
test("12: a test database per worker has the policy", async () => {
  const worker = await databasePerWorker(TESTS, { appUrl: appAt(TESTS) });
  expect(worker.url.endsWith(`/conf_tests_w${process.env.JEST_WORKER_ID}`)).toBe(true);
  await seed(worker.url);
  const p = new pg.Pool({ connectionString: worker.appUrl });
  const a = authz(p);
  try {
    await a.check();
    expect(await a.transaction(async (c) => (await c.query("SELECT id FROM app.projects ORDER BY id")).rows.map((r) => r.id), "2"))
      .toEqual([2, 3]);
  } finally {
    await p.end();
  }
});

// 13: the app refuses to start on a connection that skips row-level security (test.sh starts it so); the check
// it runs, in the app's code
test("13: refuses a connection that skips RLS", async () => {
  const ownerPool = new pg.Pool({ connectionString: OWNER });
  try {
    const e = await authz(ownerPool).check().catch((err: unknown) => err);
    expect(e).toBeInstanceOf(ConnectionProblem);
    expect((e as Error).message).toMatch(/owner/);
    await expect(withAuthz(drizzle(ownerPool)).check()).rejects.toBeInstanceOf(ConnectionProblem);
  } finally {
    await ownerPool.end();
  }
  await sql.check();
  await db.check();
  await pgjs.check();
});

// queries by permission: set checks, and one call for a list's buttons
test("queries by permission", async () => {
  expect(await ids(await fetch(`${SERVER}/api/projects/editable`, as("3")))).toEqual([1]);
  expect(await ids(await fetch(`${SERVER}/api/projects/buttons`, as("3")))).toEqual({ "1": ["edit", "view"], "3": ["view"] });
  expect(await ids(await fetch(`${SERVER}/api/projects/visible?limit=1`, as("3")))).toEqual(["1"]);
  expect(await actingAs("3", () => db.transaction((tx) =>
    tx.select({ id: projects.id }).from(projects).where(inIds(projects.id, "project", "edit"))))).toEqual([{ id: 1 }]);
});

// sharing from the app's own routes: who may share is the policy's (viewer is shared by edit), and the database
// says no
test("a share made in the app's own code", async () => {
  const shares = (who: string) => fetch(`${SERVER}/api/projects/1/shares`, as(who));
  const change = (method: string, who: string, user: number) => fetch(`${SERVER}/api/projects/1/shares`, as(who, json(method, { user })));
  const stranger = await change("POST", "2", 2);       // bo can't see project 1: why, as for one that isn't there
  expect([stranger.status, await stranger.json()]).toEqual([403, { type: "https://rowstile.dev/problems/refused",
    title: "Forbidden", status: 403, detail: "you cannot share project 1", table: null, command: null,
    why: ["no   you have no access to project 1"], code: "AZ705" }]);
  expect((await change("POST", "3", 2)).status).toBe(204);        // cy, a member, edits it
  expect(await ids(await fetch(`${SERVER}/api/notes`, as("2")))).toEqual([1, 2, 3, 4]);
  expect(await ids(await shares("1"))).toEqual([{ relation: "viewer", user: "2" }]);   // its owner, who holds share
  const viewer = await shares("2");                     // bo views it now, and still may not share it
  expect([viewer.status, (await viewer.json() as { detail: string }).detail]).toEqual([403, "you cannot see the shares of project 1"]);
  expect((await change("DELETE", "3", 2)).status).toBe(204);
  expect(await ids(await shares("1"))).toEqual([]);
});

// 16: a call the database turns down that is no refusal answers as its code's page says, with the database's
// words, through the app's routes and its error handler (Express's: problems in src/app.ts)
describe("16: the database's answers as their codes' pages say", () => {
  const problem = (kind: string, title: string, status: number, detail: string, code: string) =>
    ({ type: `https://rowstile.dev/problems/${kind}`, title, status, detail, code });
  const refused = (detail: string, code: string) => ({ type: "https://rowstile.dev/problems/refused", title: "Forbidden",
    status: 403, detail, table: null, command: null, why: [], code });
  const answer = async (r: Response) => [r.status, r.headers.get("content-type"), await r.json()];
  const problemJson = "application/problem+json; charset=utf-8";
  let readOnly = "";                                    // an API key of ann's that may only read
  beforeEach(async () => {
    readOnly = await owner(async (c) => {
      await c.query("BEGIN");
      await c.query("SELECT authz.act_as('user', '1')");
      const k = (await c.query<{ k: string }>("SELECT authz.create_api_key('ro', 'read') AS k")).rows[0]?.k ?? "";
      await c.query("COMMIT");
      return k;
    });
  });

  test("16: each code through the app's routes", async () => {
    const call = (who: string | null, path: string, init: RequestInit = {}) => fetch(`${SERVER}${path}`, as(who, init));
    const key = (k: string, init: RequestInit = {}) => ({ ...init, headers: { "x-api-key": k } });
    const cases: [string, Promise<Response>, unknown][] = [
      ["AZ708", call("1", "/api/projects/1/shares", json("POST", { user: 99 })),
        problem("not-found", "Not Found", 404, "there is no user 99", "AZ708")],
      ["AZ708", call("1", "/api/keys/987654", { method: "DELETE" }),
        problem("not-found", "Not Found", 404, "no API key 987654 of yours", "AZ708")],
      ["AZ710", call("1", "/api/projects/visible?limit=-1"),
        problem("bad-argument", "Bad Request", 400, "the page size must not be negative (got -1)", "AZ710")],
      ["AZ710", call("2", "/api/projects/1/requests", json("POST", {})),
        problem("bad-argument", "Bad Request", 400, "say why you need it", "AZ710")],
      ["AZ714", call(null, "/api/projects/1/requests", json("POST", { reason: "the review" })),
        problem("not-signed-in", "Unauthorized", 401, "sign in first", "AZ714")],
      ["AZ703", call("1", "/api/key/projects", key("ak_nope")),
        problem("not-signed-in", "Unauthorized", 401, "invalid API key", "AZ703")],
      ["AZ713", call("1", "/api/folders/1", json("PATCH", { parent_id: 2 })),
        problem("conflict", "Conflict", 409, "folder 1 cannot be moved inside itself", "AZ713")],
      ["AZ705", call("2", "/api/projects/1/shares"), refused("you cannot see the shares of project 1", "AZ705")],
      ["AZ704", call("1", "/api/keys", key(readOnly, json("POST", { name: "more" }))),
        refused("this session is read-only (viewing as someone else, or a read-only token)", "AZ704")],
    ];
    for (const [code, r, want] of cases) {
      expect([code, ...await answer(await r)]).toEqual([code, (want as { status: number }).status, problemJson, want]);
    }
    // what works: a key's own requests, as its user; a folder moved where it is already; a request with a reason
    expect(await ids(await call(null, "/api/key/projects", key(readOnly)))).toEqual([1, 3]);
    expect((await call("1", "/api/folders/2", json("PATCH", { parent_id: 1 }))).status).toBe(200);
    expect((await call("3", "/api/projects/2/requests", json("POST", { reason: "the review" }))).status).toBe(201);
    // the app's mistake stays an error, Express's 500: a share the policy doesn't declare (AZ706)
    const member = await call("1", "/api/projects/1/shares", json("POST", { user: 2, relation: "member" }));
    expect([member.status, member.headers.get("content-type")]).toEqual([500, expect.stringMatching(/^text\/html/)]);
  });

  // each code through the error handler, as the app's routes use it: a small Express app of its own with the
  // app's handler, a route per call, and after it a handler for what it passes on (Express's own would answer 500)
  test("16: each code through the error handler, and the app's mistakes passed on", async () => {
    const one = new pg.Pool({ connectionString: APP, max: 1 });
    const a = authz(one);
    const calls: Record<string, [string | null, () => Promise<unknown>]> = {
      nobody: ["1", () => sql.share("project", 1, "viewer", "user", 99)],
      negative: ["1", () => db.list("project", "view", { limit: -1 })],
      signInFirst: [null, () => pgjs.requestAccess("project", 1, "viewer", "the review")],
      loginRefused: ["1", () => a.query("SELECT authz.login_key('ak_nope')")],
      inside: ["1", () => db.transaction((tx) => tx.execute(sqlTag`UPDATE app.folders SET parent_id = 2 WHERE id = 1`))],
      shares: ["2", () => pgjs.listShares("project", 1)],
      scoped: ["1", () => a.transaction(async (c) => {
        await c.query("SELECT authz.login_key($1)", [readOnly]);
        return c.query("SELECT authz.create_api_key('more')");
      })],
      // a call that is for users, made by a service (rowstile help AZ715): a refusal too
      service: [null, () => a.transaction(async (c) => c.query("SELECT authz.create_api_key('mine')"), ["service", 1])],
      // the app's mistakes: a share the policy doesn't declare (AZ706), a name not in the policy (AZ707), who is
      // signed in changed by hand (AZ702, not NotSignedIn)
      undeclared: ["1", () => sql.share("project", 1, "member" as never, "user", 2)],
      unnamed: ["1", () => sql.list("nosuch" as never, "view" as never)],
      byHand: ["1", () => a.transaction(async (c) => {
        await c.query("SELECT set_config('authz.user_id', '2', true)");
        return c.query("SELECT count(*) FROM app.notes");
      })],
    };
    const passedOn: unknown[] = [];
    const probe = express();
    probe.get("/:name", async (req, res) => {
      const [who, call] = calls[req.params.name] ?? [null, async () => undefined];
      await actingAs(who, call);
      res.status(204).end();
    });
    probe.use(problems);
    probe.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
      passedOn.push(err);
      res.status(500).end();
    });
    const server = probe.listen(0);
    await new Promise((ready) => server.once("listening", ready));
    const at = `http://localhost:${(server.address() as AddressInfo).port}`;
    try {
      const got: Record<string, unknown> = {};
      for (const name of Object.keys(calls)) {
        const r = await fetch(`${at}/${name}`);
        got[name] = r.status === 500 ? 500 : await answer(r);
      }
      expect(got).toEqual({
        nobody: [404, problemJson, problem("not-found", "Not Found", 404, "there is no user 99", "AZ708")],
        negative: [400, problemJson, problem("bad-argument", "Bad Request", 400, "the page size must not be negative (got -1)", "AZ710")],
        signInFirst: [401, problemJson, problem("not-signed-in", "Unauthorized", 401, "sign in first", "AZ714")],
        loginRefused: [401, problemJson, problem("not-signed-in", "Unauthorized", 401, "invalid API key", "AZ703")],
        inside: [409, problemJson, problem("conflict", "Conflict", 409, "folder 1 cannot be moved inside itself", "AZ713")],
        shares: [403, problemJson, refused("you cannot see the shares of project 1", "AZ705")],
        scoped: [403, problemJson, refused("this session is read-only (viewing as someone else, or a read-only token)", "AZ704")],
        service: [403, problemJson, refused("authz.create_api_key for oneself is for users, not services (service 1 is signed in)", "AZ715")],
        undeclared: 500, unnamed: 500, byHand: 500,
      });
      const thrown = (e: unknown) => [e instanceof NotSignedIn, errorCode(e), sqlstate(e), (e as Error).message];
      expect(passedOn.map(thrown)).toEqual([
        [false, "AZ706", "P0001", expect.stringContaining("the policy does not allow sharing project.member with user")],
        [false, "AZ707", "P0001", expect.stringContaining("no permission nosuch.view in the policy")],
        [false, "AZ702", "28000", "who is signed in was changed after signing in"],
      ]);
    } finally {
      server.close();
      await one.end();
    }
  });
});

// 14: after a policy change and a new migration, the app works with the new generated names
test("14: a policy change ships as the next migration", () => {
  const work = join(HERE, ".work", "check14");
  rmSync(work, { recursive: true, force: true });
  for (const part of ["db", "drizzle", "rowstile.toml", "drizzle.config.ts", "src/schema.ts", "src/authz.gen.ts"]) {
    cpSync(join(HERE, part), join(work, part), { recursive: true });
  }
  const policy = join(work, "db", "policy.authz");
  writeFileSync(policy, readFileSync(policy, "utf8").replace("  can read = recipient\n", "  can read = recipient\n  can reply = recipient\n"));
  execFileSync(PYTHON, [CLI, "migrate", "--name", "reply"], { cwd: work, stdio: "pipe" });
  const migrate = run("drizzle-kit", ["migrate"], work);
  expect([migrate.status, migrate.stderr]).toEqual([0, ""]);
  execFileSync(PYTHON, [CLI, "client"], { cwd: work, stdio: "pipe" });
  expect(readFileSync(join(work, "src", "authz.gen.ts"), "utf8")).toContain('"reply"');
  writeFileSync(join(work, "use.ts"), 'import "./src/authz.gen.js";\nimport type { Permission } from "@rowstile/client";\n' +
    'export const p: Permission<"message"> = "reply";\n');
  writeFileSync(join(work, "tsconfig.json"), JSON.stringify({ extends: "../../tsconfig.json", compilerOptions: { noEmit: true },
    include: ["use.ts", "src/authz.gen.ts"], exclude: [] }));
  const tsc = run("tsc", ["-p", "tsconfig.json"], work);
  expect([tsc.status, tsc.stdout]).toEqual([0, ""]);
});

test("14: ... and the running app has the new permission", async () => {
  const sent = await fetch(`${SERVER}/api/inbox/quietly`, as("1", json("POST", { recipient_id: 2, body: "hi" })));
  expect(sent.status).toBe(202);
  const [message] = await ids(await fetch(`${SERVER}/api/inbox`, as("2"))) as number[];
  expect(await ids(await fetch(`${SERVER}/api/inbox/${message}/perms`, as("2")))).toEqual(["read", "reply"]);
  expect(current()).toBeUndefined();
});

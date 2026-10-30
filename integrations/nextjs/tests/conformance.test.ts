// The conformance suite (integrations/README.md): the same checks for every stack. This is Next.js
// (App Router), Prisma 7 on node-postgres, Prisma Migrate; then pg, postgres.js and Drizzle without Prisma.
// test.sh does check 11 (a fresh database: migrate, the policy's tests, then Prisma's own diff shows no
// change) and starts the servers these checks call, before they run.
import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import postgres from "postgres";
import { drizzle } from "drizzle-orm/node-postgres";
import { drizzle as drizzlePostgres } from "drizzle-orm/postgres-js";
import { eq, sql as sqlTag } from "drizzle-orm";
import { integer, numeric, pgSchema, serial, text, varchar } from "drizzle-orm/pg-core";
import { afterAll, beforeEach, describe, expect, test } from "vitest";
import { actingAs, beforeSignIn, ConnectionProblem, current, errorCode, NotSignedIn, sqlstate, translate } from "@rowstile/client";
import { idShown, Refused, refusal, verdict, type AuthzCalls } from "@rowstile/client";
import { describe as describePrincipal, parsePrincipal, principal } from "@rowstile/client";
import { authzRoutes } from "@rowstile/next";
import { authz as rowstile } from "@rowstile/pg";
import { calls, changes } from "@rowstile/pg";
import { authz as postgresAuthz } from "@rowstile/postgres";
import { expect as drizzleExpect, inIds, withAuthz } from "@rowstile/drizzle";
import { ids as drizzleIds, queryable as drizzleQueryable } from "@rowstile/drizzle";
import { databasePerWorker } from "@rowstile/vitest";
import { PrismaPg } from "@prisma/adapter-pg";
import { authz, signedIn } from "@rowstile/prisma";
import { PrismaClient } from "@/generated/prisma/client.ts";
import { db, pool } from "@/db";
import { digest } from "@/jobs";
import { APP, EXPECTED, FEED, OWNER, SERVER, SERVER_LOG, SERVER_ONE, as, seed } from "./data";

const HERE = dirname(dirname(fileURLToPath(import.meta.url)));
const ROOT = join(HERE, "..", "..");
const CLI = join(ROOT, "core", "cli", "rowstile_cli.py");
const PYTHON = process.env.PYTHON ?? "python3";
// the tools' own scripts, run with this Node
const TOOL: Record<string, string> = {
  tsc: join(ROOT, "node_modules", "typescript", "bin", "tsc"),
  prisma: join(ROOT, "node_modules", "prisma", "build", "index.js"),
};
const run = (tool: string, args: string[], cwd: string) =>
  spawnSync(process.execPath, [TOOL[tool], ...args], { cwd, encoding: "utf8", env: process.env });

beforeEach(seed);
afterAll(async () => {
  await pool.end();
  await db.$disconnect();
});

const ids = (html: string) => [...html.matchAll(/data-note="(\d+)"/g)].map((m) => Number(m[1]));

// 1, 2: a list shows only the user's rows; signed out on purpose, only what anyone may see
test("1, 2: lists show what each may see", async () => {
  for (const [user, notes] of Object.entries(EXPECTED)) {
    const r = await fetch(`${SERVER}/api/notes`, as(user || null));
    expect(await r.json(), user).toEqual(notes);
  }
  expect(await (await fetch(`${SERVER}/api/projects`)).json()).toEqual([3]);
});

// 3: not signed in at all: the not-signed-in error (AZ701), naming act_as
test("3: not signed in is an error that says how", async () => {
  const c = new pg.Client({ connectionString: APP });
  await c.connect();
  try {
    await c.query("BEGIN");
    const e = await c.query("SELECT count(*) FROM app.notes").catch((err) => err);
    expect(e.code).toBe("28000");
    expect(e.hint).toContain("act_as");
    expect(translate(e)).toBeInstanceOf(NotSignedIn);
    expect(errorCode(e)).toBe("AZ701");                 // rowstile help AZ701
    expect((translate(e) as NotSignedIn).code).toBe("AZ701");
  } finally {
    await c.end();
  }
});

// 4: one pooled connection, Ann then Bob: Bob never sees Ann's rows
test("4: a pooled connection carries no one over", async () => {
  for (const user of ["1", "2", "", "3", "2"]) {
    expect(await (await fetch(`${SERVER_ONE}/api/notes`, as(user || null))).json(), user).toEqual(EXPECTED[user]);
  }
});

// 5: concurrent requests never mix users; nor do Prisma's findUnique calls, which it answers together
test("5: concurrent requests never mix users", async () => {
  const users = Array.from({ length: 40 }, (_, i) => ["1", "2", "3", ""][i % 4]);
  const got = await Promise.all(users.map((u) => fetch(`${SERVER}/api/notes`, as(u || null)).then((r) => r.json())));
  expect(got).toEqual(users.map((u) => EXPECTED[u]));
  const one = await Promise.all(users.map((u) => actingAs(u || null, () => db.note.findUnique({ where: { id: 1 } }))));
  expect(one.map((n) => n?.id ?? null)).toEqual(users.map((u) => (u === "1" || u === "3" ? 1 : null)));
});

// Prisma starts an array transaction from whichever caller came first in that tick: refused, with what to use
test("5: Prisma's array transactions are refused", async () => {
  await expect(actingAs("1", () => db.$transaction([db.note.findMany()]))).rejects.toThrow("$transaction(async (tx)");
});

// A client that wasn't extended with authz() would answer the findUnique calls of one tick with one query,
// signed in as the first caller: it is refused whenever it is used, though another client is extended
test("5: a client that isn't extended is refused", async () => {
  const own = new pg.Pool({ connectionString: APP, max: 5 });
  const plain = new PrismaClient({ adapter: signedIn(new PrismaPg(own)) });
  const extendedLater = plain.$extends(authz()).$extends({ name: "the app's own" });
  try {
    const users = Array.from({ length: 20 }, (_, i) => ["1", "2", "3", ""][i % 4]);
    const got = await Promise.all(users.map((u) =>
      actingAs(u || null, () => plain.note.findUnique({ where: { id: 1 } })).then((n) => n?.id ?? null, (e: Error) => e.message)));
    for (const g of got) expect(g).toContain("isn't extended with authz()");
    await expect(actingAs("1", () => plain.note.findMany())).rejects.toThrow("isn't extended with authz()");
    await expect(actingAs("1", () => plain.$transaction([plain.note.findMany()]))).rejects.toThrow("isn't extended with authz()");
    await expect(actingAs("1", () => plain.$transaction((tx) => tx.note.findMany()))).rejects.toThrow("isn't extended with authz()");
    // the extended one, with an extension of the app's after it, answers each caller
    const one = await Promise.all(users.map((u) => actingAs(u || null, () => extendedLater.note.findUnique({ where: { id: 1 } }))));
    expect(one.map((n) => n?.id ?? null)).toEqual(users.map((u) => (u === "1" || u === "3" ? 1 : null)));
    expect(await actingAs("2", () => extendedLater.$transaction((tx) => tx.note.count()))).toBe(2);
    expect(await actingAs("3", () => extendedLater.$authz.perms("note", 4))).toEqual(["edit", "view"]);
    // ... and inside the extended client's own transaction too: its callback is the app's code, and the plain
    // client's findUnique calls there would still be answered together, as the first caller (four at once: each
    // transaction holds one of the pool's five connections, and the plain client's query needs another)
    const inside = await Promise.all(users.slice(0, 4).map((u) =>
      actingAs(u || null, () => extendedLater.$transaction(() => plain.note.findUnique({ where: { id: 1 } })))
        .then((n) => n?.id ?? null, (e: Error) => e.message)));
    for (const g of inside) expect(g).toContain("isn't extended with authz()");
    // ... and inside the app's own extensions, on either side of authz(): their hooks are the app's code too.
    // Each hook is called once for each call (a findUnique's own transaction doesn't run them again), and the
    // plain client is refused there: note 1, which users 1 and 3 may see, reaches nobody through it
    const called: string[] = [];
    const reached: unknown[] = [];
    const hook = (name: string) => ({
      name,
      query: { async $allOperations({ operation, args, query }: { operation: string; args: unknown; query: (a: unknown) => Promise<unknown> }) {
        called.push(`${name} ${operation}`);
        reached.push(await plain.note.findUnique({ where: { id: 1 } }).then((n) => n?.id ?? null,
          (e: Error) => (e.message.includes("isn't extended with authz()") ? "refused" : e.message)));
        return query(args);
      } },
    });
    const both = plain.$extends(hook("before")).$extends(authz()).$extends(hook("after")).$extends({
      result: { note: { shout: { needs: { body: true }, compute: (n) => n.body.toUpperCase() } } },
    });
    const four = await Promise.all(users.slice(0, 4).map((u) => actingAs(u || null, () => both.note.findUnique({ where: { id: 1 } }))));
    expect(four.map((n) => n?.id ?? null)).toEqual([1, null, 1, null]);
    expect(four[0]?.shout).toBe(four[0]?.body.toUpperCase());   // the app's computed fields, on a findUnique too
    expect([...called].sort()).toEqual([...Array(4).fill("after findUnique"), ...Array(4).fill("before findUnique")]);
    expect(reached).toEqual(Array(8).fill("refused"));
    called.length = reached.length = 0;
    expect((await actingAs("2", () => both.note.findMany())).length).toBe(2);
    expect(await actingAs("2", () => both.$transaction((tx) => tx.note.count()))).toBe(2);
    expect(await actingAs("3", () => both.$authz.perms("note", 4))).toEqual(["edit", "view"]);
    expect(called).toEqual(["before findMany", "after findMany", "before count", "after count", "before $queryRawUnsafe", "after $queryRawUnsafe"]);
    expect(reached).toEqual(Array(6).fill("refused"));
  } finally {
    await plain.$disconnect();
    await own.end().catch(() => undefined);
  }
});

// 6: a refused insert: 403, with the problem body naming the rule
test("6: a refused insert says which rule", async () => {
  const r = await fetch(`${SERVER}/api/notes`, as("2", { method: "POST", body: JSON.stringify({ project_id: 3, body: "hi" }) }));
  expect(r.status).toBe(403);
  expect(r.headers.get("content-type")).toBe("application/problem+json");
  const body = await r.json();
  expect(body.table).toBe("app.notes");
  expect(body.command).toBe("insert");
  expect(body.detail).toContain("user 2 may not insert this row into app.notes");
  expect(body.why.some((line: string) => line.includes("project.edit"))).toBe(true);
});

// 7: an update of a hidden row: 404; of a visible row the user may not edit: 403, with the reason
test("7: hidden is 404, not allowed is 403", async () => {
  const patch = (id: number, user: string) =>
    fetch(`${SERVER}/api/notes/${id}`, as(user, { method: "PATCH", body: JSON.stringify({ body: "x" }) }));
  const hidden = await patch(1, "2");
  const refused = await patch(1, "3");
  const mine = await patch(4, "3");
  const gone = await fetch(`${SERVER}/api/notes/2`, as("1", { method: "DELETE" }));
  const no = await fetch(`${SERVER}/api/notes/1`, as("3", { method: "DELETE" }));
  expect(hidden.status).toBe(404);
  expect(refused.status).toBe(403);
  const why = await refused.json();
  expect(why.command).toBe("update");
  expect(why.code).toBe("AZ709");                       // rowstile help AZ709
  expect(why.why.some((line: string) => line.includes("edit"))).toBe(true);
  // worded as the database words a refused insert: who, the command, the row, the table
  expect(why.detail).toBe("permission denied: user 3 may not update row 1 of app.notes");
  expect(mine.status).toBe(200);
  expect(gone.status).toBe(404);
  expect(no.status).toBe(403);
  expect((await no.json()).detail).toBe("permission denied: user 3 may not delete row 1 of app.notes");
  // a key of several columns is spelled as the database writes it, in a 403 and a 404 alike
  expect([7, [7], [1, 2], ["a b", "x,y"], ["", 'q"t'], ["b\\s", "(1)"]].map((k) => idShown(k as never)))
    .toEqual(["7", "7", "(1,2)", '("a b","x,y")', '("","q""t")', '("b\\\\s","(1)")']);
  expect(verdict("app.members", "delete", [1, 2], ["no   delete : manage"], "service 3").message)
    .toBe("permission denied: service 3 may not delete row (1,2) of app.members");
  expect(verdict("app.members", "delete", [1, 2], null).message).toBe("app.members (1,2) not found");
  // in an interactive transaction too, and as the matchers say it
  await expect(actingAs("3", () => db.$transaction((tx) => tx.note.update({ where: { id: 1 }, data: { body: "x" } }))))
    .rejects.toBeRefused("update", "note.edit");
  await expect(actingAs("2", () => db.note.delete({ where: { id: 1 } }))).rejects.toBeNotFound();
  // a read that must find its row: hidden and absent alike are NotFound, not Prisma's own error (a 500)
  await expect(actingAs("2", () => db.note.findUniqueOrThrow({ where: { id: 1 } }))).rejects.toBeNotFound();
  await expect(actingAs("2", () => db.note.findFirstOrThrow({ where: { id: 1 } }))).rejects.toBeNotFound();
  await expect(actingAs("1", () => db.note.findUniqueOrThrow({ where: { id: 987654 } }))).rejects.toBeNotFound();
  expect((await actingAs("3", () => db.note.findUniqueOrThrow({ where: { id: 1 } }))).id).toBe(1);
});

// 8: an insert read back works when the select rule allows it, and is explained when not
test("8: insert, then read back", async () => {
  const post = (path: string, user: string, body: object) =>
    fetch(`${SERVER}${path}`, as(user, { method: "POST", body: JSON.stringify(body) }));
  const ok = await post("/api/notes", "1", { project_id: 1, body: "new" });
  const unreadable = await post("/api/inbox", "1", { recipient_id: 2, body: "hi bo" });
  const quiet = await post("/api/inbox/quietly", "1", { recipient_id: 2, body: "hi bo" });
  expect(ok.status).toBe(201);
  expect((await ok.json()).id).toBeGreaterThan(100);
  expect(unreadable.status).toBe(403);
  const why = await unreadable.json();
  expect(why.command).toBe("select");
  expect(why.table).toBe("app.inbox");
  expect(why.detail).toContain("may not see the row as written");
  expect(quiet.status).toBe(202);
  // a model with no @@map, in the app schema (feedback, which only the project's owner reads): its table, as the
  // policy names it, is its name with the schema
  const feedback = await actingAs("3", () => db.feedback.create({ data: { project_id: 1, author_id: 3, body: "nice" } }))
    .catch((e: unknown) => e);
  expect(feedback instanceof Refused && [feedback.table, feedback.command]).toEqual(["app.feedback", "select"]);
  expect((await actingAs("1", () => db.feedback.create({ data: { project_id: 1, author_id: 1, body: "mine" } }))).body).toBe("mine");
});

// a transaction in a page's after(), once the page is sent: Next has no render to keep it out of a cache, and
// @rowstile/next lets it sign in (Next's own words for that, as this version of Next says them)
test("after(): a transaction once the page is sent signs in and runs", async () => {
  const r = await fetch(`${SERVER}/later`, as("1"));
  expect([r.status, await r.text()]).toEqual([200, expect.stringContaining("sent once the page is")]);
  const owner = new pg.Client({ connectionString: OWNER });
  await owner.connect();
  try {
    const sent = async () => (await owner.query("SELECT sender_id, recipient_id FROM app.inbox WHERE body = 'later'")).rows;
    for (let i = 0; i < 100 && (await sent()).length === 0; i++) await new Promise((r) => setTimeout(r, 100));
    expect(await sent()).toEqual([{ sender_id: 1, recipient_id: 2 }]);
  } finally {
    await owner.end();
  }
});

// 9: the generated names type-check, and a wrong permission name doesn't
test("9: the generated names type-check", () => {
  execFileSync(PYTHON, [CLI, "client"], { cwd: HERE, stdio: "pipe" });
  const dir = join(HERE, ".work", "typecheck");
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const tsconfig = (file: string) => JSON.stringify({
    extends: "../../tsconfig.json",
    compilerOptions: { incremental: false, plugins: [] }, exclude: [],
    include: [file, "../../src/authz.gen.ts"],
  });
  const use = (perm: string) => `import { db } from "../../src/db.ts";\nimport type { Permission } from "@rowstile/client";\n` +
    `export const ok = db.$authz.can("note", 1, "${perm}");\nexport const p: Permission<"project"> = "view";\n`;
  const check = (name: string, perm: string) => {
    writeFileSync(join(dir, `${name}.ts`), use(perm));
    writeFileSync(join(dir, `tsconfig.${name}.json`), tsconfig(`${name}.ts`));
    return run("tsc", ["-p", `tsconfig.${name}.json`, "--noEmit"], dir);
  };
  const good = check("good", "edit");
  const bad = check("bad", "edt");
  expect(good.status, good.stdout + good.stderr).toBe(0);
  expect(bad.status).not.toBe(0);
  expect(bad.stdout).toContain('"edt"');
});

// 10: a background job signs in as a service principal
test("10: a job acts for its service", async () => {
  const { count, who } = await actingAs("3", () => digest());      // whatever started it
  expect(who).toEqual({ type: "service", id: "1" });
  expect(count).toBe(2);                                            // project 1 (it is added to) and the public one
});

// ... and only when the code names it: an id is a user's, whatever it holds (ids come from outside)
test("10: an id with a colon is a user's, not a service", async () => {
  expect(principal("service:1")).toEqual({ type: "user", id: "service:1" });
  expect(principal(["service", 1])).toEqual({ type: "service", id: "1" });
  expect(await actingAs("service:1", async () => current())).toEqual({ type: "user", id: "service:1" });
  // what describe() wrote, read back, for text the app wrote itself (a job's argument): every principal as itself,
  // a user whose id holds a colon or is "nobody" too
  const users = ["service:1", "nobody", "google-oauth2:117", "user:5", "a:b", ":", "(1,a:b)", "(1,2)", "", "42"];
  const every = [...users.map((u) => principal(u)), principal(null), principal(["service", 1]),
    principal(["service", "3:4"]), principal(["service", "(1,2)"])];
  expect(every.map((p) => parsePrincipal(describePrincipal(p)))).toEqual(every);
  expect(["service:1", "nobody", "42"].map((u) => describePrincipal(principal(u)))).toEqual(["user:service:1", "user:nobody", "42"]);
  expect([describePrincipal(principal(["service", 1])), describePrincipal(principal(null))]).toEqual(["service:1", "nobody"]);
  expect(parsePrincipal("42")).toEqual({ type: "user", id: "42" });
});

// 12: the framework's test database has the policy: a database per worker, copied from the migrated one
test("12: a test database per worker has the policy", async () => {
  const tests = process.env.ROWSTILE_TESTS_DSN;
  expect(tests, "ROWSTILE_TESTS_DSN (test.sh sets it)").toBeTruthy();
  const appTests = new URL(APP);
  appTests.pathname = new URL(tests!).pathname;
  const worker = await databasePerWorker(tests!, { appUrl: appTests.toString() });
  expect(worker.url).toMatch(/_w\d+$/);
  const owner = new pg.Client({ connectionString: worker.url });
  await owner.connect();
  await owner.query("INSERT INTO app.users VALUES (1, 'ann'), (2, 'bo'); INSERT INTO app.projects VALUES (1, 1, 'Plans', false)");
  await owner.end();
  const p = new pg.Pool({ connectionString: worker.appUrl });
  const a = rowstile(p);
  try {
    await a.check();
    expect(await a.transaction(async (c) => (await c.query("SELECT id FROM app.projects")).rows.map((r) => r.id), "1")).toEqual([1]);
    expect(await a.transaction(async (c) => (await c.query("SELECT id FROM app.projects")).rows, "2")).toEqual([]);
  } finally {
    await p.end();
  }
});

// 13: the app refuses to start on a connection that skips row-level security
test("13: refuses a connection that skips RLS", async () => {
  const ownerPool = new pg.Pool({ connectionString: OWNER });
  try {
    const e = await rowstile(ownerPool).check().catch((err) => err);
    expect(e).toBeInstanceOf(ConnectionProblem);
    expect(e.message).toMatch(/owner|superuser/);
  } finally {
    await ownerPool.end();
  }
  await db.$authz.check();
});

// queries by permission: set checks, and one call for a list's buttons
test("queries by permission", async () => {
  expect(await (await fetch(`${SERVER}/api/projects/editable`, as("3"))).json()).toEqual([1]);
  expect(await (await fetch(`${SERVER}/api/projects/buttons`, as("3"))).json()).toEqual({ "1": ["edit", "view"], "3": ["view"] });
});

// sharing from a route handler: who may share is the policy's (viewer is shared by edit), and the database says no
test("a share made in the app's own code", async () => {
  const share = (as_: string, user: number) =>
    fetch(`${SERVER}/api/projects/1/shares`, as(as_, { method: "POST", body: JSON.stringify({ user }) }));
  const stranger = await share("2", 2);                 // bo can't see project 1
  expect(stranger.status).toBe(403);
  const why = await stranger.json();
  expect(why.detail).toBe("you cannot share project 1");
  expect([why.code, why.table, why.command]).toEqual(["AZ705", null, null]);   // the database's code; a share has no table
  expect((await share("3", 2)).status).toBe(204);       // cy, a member, edits it
  expect(await (await fetch(`${SERVER}/api/notes`, as("2"))).json()).toEqual([1, 2, 3, 4]);
  expect((await share("2", 2)).status).toBe(403);       // a viewer still may not share
  // 16: with someone who isn't there: 404, in the database's words (rowstile help AZ708)
  const nobody = await share("1", 99);
  expect([nobody.status, nobody.headers.get("content-type"), await nobody.json()]).toEqual([404, "application/problem+json", {
    type: "https://rowstile.dev/problems/not-found", title: "Not Found", status: 404, detail: "there is no user 99", code: "AZ708",
  }]);
});

// the same on pg, without Prisma (docs/stacks/nextjs.md, "Next.js with pg"): a read, and the sharing dialog
test("Next.js with pg: reads filtered, and sharing as the database allows", async () => {
  expect(await (await fetch(`${SERVER}/api/pg/notes`, as("2"))).json()).toEqual(EXPECTED["2"]);
  const shares = async (as_: string) => (await fetch(`${SERVER}/api/pg/projects/1/shares`, as(as_))).json();
  const change = (method: string, as_: string, user: number) =>
    fetch(`${SERVER}/api/pg/projects/1/shares`, as(as_, { method, body: JSON.stringify({ user }) }));
  const stranger = await change("POST", "2", 2);       // bo can't see project 1
  expect([stranger.status, (await stranger.json()).detail]).toEqual([403, "you cannot share project 1"]);
  expect((await change("POST", "3", 2)).status).toBe(204);
  expect(await shares("1")).toEqual([{ relation: "viewer", user: "2" }]);   // its owner, who holds share
  expect((await fetch(`${SERVER}/api/pg/projects/1/shares`, as("2"))).status).toBe(403);   // bo views, may not share
  expect((await change("DELETE", "3", 2)).status).toBe(204);
  expect(await shares("1")).toEqual([]);
});

// 16: a folder moved inside one of its own subfolders, by the app's own route: 409, in the database's words
// (rowstile help AZ713)
test("a folder moved inside itself is a conflict", async () => {
  const move = (id: number, parent_id: number | null) =>
    fetch(`${SERVER}/api/folders/${id}`, as("1", { method: "PATCH", body: JSON.stringify({ parent_id }) }));
  const inside = await move(1, 2);
  expect([inside.status, inside.headers.get("content-type"), await inside.json()]).toEqual([409, "application/problem+json", {
    type: "https://rowstile.dev/problems/conflict", title: "Conflict", status: 409,
    detail: "folder 1 cannot be moved inside itself", code: "AZ713",
  }]);
  expect((await move(2, 1)).status).toBe(200);         // where it is already: nothing in the way
});

// a write refused inside an interactive transaction, on a pool of one: why is asked inside the transaction, which
// holds the one connection, so the answer comes at once (asked outside, it waited for Prisma's timeout, 5 s)
test("a refusal inside a transaction, on a pool of one, is explained at once", async () => {
  const append = async (id: number, user: string) => {
    const start = Date.now();
    const r = await fetch(`${SERVER_ONE}/api/notes/${id}/append`, as(user, { method: "POST", body: JSON.stringify({ text: "!" }) }));
    return { status: r.status, body: await r.json(), ms: Date.now() - start };
  };
  const refused = await append(1, "3");                // cy sees note 1, may not edit it
  expect([refused.status, refused.body.detail]).toEqual([403, "permission denied: user 3 may not update row 1 of app.notes"]);
  const hidden = await append(1, "2");                 // bo doesn't see it
  expect([hidden.status, hidden.body.detail]).toEqual([404, "app.notes 1 not found"]);
  expect([refused.ms, hidden.ms].every((ms) => ms < 2500), `${refused.ms} ms, ${hidden.ms} ms`).toBe(true);
  expect((await append(4, "3")).status).toBe(200);     // cy's own
  // the transaction is still usable after the refusal: what the app does next in it is kept
  const kept = await actingAs("3", () => db.$transaction(async (tx) => {
    await tx.note.update({ where: { id: 1 }, data: { body: "x" } }).catch((e: unknown) => e);
    return tx.note.update({ where: { id: 4 }, data: { body: "kept" } });
  }));
  expect(kept.body).toBe("kept");
});

// 15: a signed-in page is never served from a cache to another user
test("15: signed-in pages are never cached for another user", async () => {
  for (const user of ["1", "2", "", "1", "2"]) {
    const r = await fetch(`${SERVER}/notes`, as(user || null));
    expect(r.status).toBe(200);
    expect(ids(await r.text()), user).toEqual(EXPECTED[user]);
  }
  // a page that caches what the user may see fails, instead of serving it to the next user. Why it failed is in the
  // server's log, under the digest the page shows (Next.js shows a production error by its digest alone): Next
  // refused @rowstile/next's connection() call inside the cache, which only the SDK makes. With the "use cache"
  // directive too: the page whose user comes from the request (there Next refuses the app's headers() first), and
  // the one whose user is known without it (only @rowstile/next stops that one)
  const refusedBy: Record<string, RegExp> = {
    "cached-notes": /`connection\(\)` can't be called inside `unstable_cache\(\)`/,
    "use-cache-notes": /`headers\(\)` can't be read inside `"use cache"`/,
    "use-cache-known-user": /`connection\(\)` can't be called inside `"use cache"`/,
  };
  for (const [page, why] of Object.entries(refusedBy)) {
    for (const user of ["1", "2", "1"]) {
      const { status, body, logged } = await served(page, user);
      // 200: the page streams inside <Suspense> (Cache Components), so its status is sent before the read fails;
      // what it serves holds no row, and the error is the one below
      expect(status, `${page} as ${user}`).toBe(200);
      expect(ids(body), `${page} as ${user}`).toEqual([]);
      const errors = logged.split(/^(?=⨯ )/m).filter((e) => e.includes("digest"));
      expect(errors.length, `${page} as ${user}: ${logged}`).toBe(1);
      expect(errors[0], `${page} as ${user}`).toMatch(why);
      const digest = /digest: '(\w+)'/.exec(errors[0])?.[1];
      expect(digest && body.includes(digest), `${page} as ${user}: the page shows digest ${digest}`).toBe(true);
    }
  }
});

/** A page of the first server as the user gets it, and what the server logged while it answered */
async function served(page: string, user: string | null): Promise<{ status: number; body: string; logged: string }> {
  const start = statSync(SERVER_LOG).size;
  const r = await fetch(`${SERVER}/${page}`, as(user));
  const body = await r.text();
  let logged = "";
  for (let i = 0; i < 40 && !logged.includes("digest"); i++) {      // (written as it renders; read once it is there)
    if (i) await new Promise((wait) => setTimeout(wait, 50));
    logged = readFileSync(SERVER_LOG).subarray(start).toString("utf8");
  }
  return { status: r.status, body, logged };
}

// server actions, called through the server as the page's form calls one (app/rename): the action reads who the
// request is, and a refusal comes back as { ok: false, problem }, across to the browser (Next.js would hide a thrown
// error's message)
test("server actions answer with the problem, as the request's user", async () => {
  const manifest = JSON.parse(readFileSync(join(HERE, ".next", "server", "server-reference-manifest.json"), "utf8")) as {
    node: Record<string, { exportedName?: string }>;
  };
  const action = Object.entries(manifest.node).find(([, a]) => a.exportedName === "renameNote")?.[0];
  expect(action, "renameNote in the build's server actions").toBeTruthy();
  const rename = async (user: string, id: number, body: string) => {
    const r = await fetch(`${SERVER}/rename`, {
      method: "POST",
      headers: { "x-user": user, "next-action": action!, accept: "text/x-component", "content-type": "text/plain;charset=UTF-8" },
      body: JSON.stringify([id, body]),                             // the arguments, as React sends them
    });
    const flight = await r.text();
    expect([r.status, r.headers.get("content-type")], flight).toEqual([200, "text/x-component"]);
    return returned(flight);
  };
  expect(await rename("3", 4, "mine")).toEqual({ ok: true, value: 4 });
  expect(await rename("3", 1, "x")).toEqual({ ok: false, problem: expect.objectContaining({
    status: 403, detail: "permission denied: user 3 may not update row 1 of app.notes", command: "update", code: "AZ709",
  }) });
  expect(await rename("2", 1, "x")).toEqual({ ok: false, problem: {
    type: "https://rowstile.dev/problems/not-found", title: "Not Found", status: 404, detail: "app.notes 1 not found",
  } });
  const owner = new pg.Client({ connectionString: OWNER });
  await owner.connect();
  try {
    expect((await owner.query("SELECT id, body FROM app.notes WHERE id IN (1, 4) ORDER BY id")).rows).toEqual(
      [{ id: 1, body: "plan" }, { id: 4, body: "mine" }]);
  } finally {
    await owner.end();
  }
});

/** What a server action returned, read from Next's answer: React's rows, `0:{"a":"$@1",...}` naming the row
 *  that holds it, `1:{"ok":true,...}` */
function returned(flight: string): unknown {
  const rows = new Map(flight.split("\n").filter(Boolean).map((line) => {
    const colon = line.indexOf(":");
    return [line.slice(0, colon), line.slice(colon + 1)] as const;
  }));
  const ref = (JSON.parse(rows.get("0") ?? "{}") as { a?: string }).a ?? "";
  expect(ref, flight).toMatch(/^\$@\w+$/);
  return JSON.parse(rows.get(ref.slice(2)) ?? "null");
}

describe("without Prisma", () => {
  test("pg: transactions signed in, refusals as errors", async () => {
    const p = new pg.Pool({ connectionString: APP });
    const a = rowstile(p);
    try {
      expect(await a.transaction(async (c) => (await c.query("SELECT id FROM app.notes ORDER BY id")).rows.map((r) => r.id), "2")).toEqual([2, 3]);
      await expect(actingAs("3", () => a.transaction(async (c) => {
        const r = await c.query("UPDATE app.notes SET body = 'x' WHERE id = 1");
        return a.expect(r, "app.notes", "update", 1);
      }))).rejects.toBeRefused("update");
      await expect(actingAs("2", () => a.query("INSERT INTO app.notes (project_id, author_id, body) VALUES (3, 2, 'hi')")))
        .rejects.toBeRefused("insert", "project.edit");
      expect(await actingAs("3", () => a.can("project", 1, "edit"))).toBe(true);
    } finally {
      await p.end();
    }
  });

  test("postgres.js: begin() signed in", async () => {
    const sql = postgres(APP, { max: 2 });
    const a = postgresAuthz(sql);
    try {
      const projects = await actingAs(["service", 1], () => a.begin(async (tx) => tx`SELECT id FROM app.projects ORDER BY id`));
      expect(projects.map((r) => r.id)).toEqual([1, 3]);
      await expect(a.begin(async (tx) => tx`DELETE FROM app.notes WHERE id = 3 RETURNING id`.then((rows) =>
        a.expect(rows, "app.notes", "delete", 3)), "2")).rejects.toThrow("permission denied: user 2 may not delete row 3 of app.notes");
      expect(await a.permsOf("project", [1, 3])).toEqual({ "1": [], "3": ["view"] });   // signed out
    } finally {
      await sql.end();
    }
  });

  test("Drizzle: transactions signed in, inIds, expect", async () => {
    const app = pgSchema("app");
    const projects = app.table("projects", { id: integer("id").primaryKey(), ownerId: integer("owner_id"), name: text("name") });
    const notes = app.table("notes", { id: serial("id").primaryKey(), projectId: integer("project_id"), body: text("body") });
    const p = new pg.Pool({ connectionString: APP });
    const d = drizzle(p);
    const a = withAuthz(d);
    try {
      const editable = await a.transaction((tx) => tx.select({ id: projects.id }).from(projects).where(inIds(projects.id, "project", "edit")), "3");
      expect(editable).toEqual([{ id: 1 }]);
      await expect(a.transaction(async (tx) => drizzleExpect(tx, await tx.delete(notes).where(eq(notes.id, 1)).returning(),
        "app.notes", "delete", 1), "3")).rejects.toBeRefused("delete");
      // who the transaction signed in as, asked of the database: not whoever the code around it acts for
      const said = await actingAs("1", () => a.transaction(async (tx) => drizzleExpect(tx,
        await tx.delete(notes).where(eq(notes.id, 1)).returning(), "app.notes", "delete", 1), "3")).catch((err) => err);
      expect(said.message).toBe("permission denied: user 3 may not delete row 1 of app.notes");
      const e = await d.select().from(notes).catch((err) => err);  // outside a signed-in transaction
      expect(translate(e)).toBeInstanceOf(NotSignedIn);
    } finally {
      await p.end();
    }
  });

  // the runtime's functions answer the same over every driver (permsOf's ids are one array parameter)
  test("the runtime's functions over pg, postgres.js and Drizzle", async () => {
    const p = new pg.Pool({ connectionString: APP });
    const sql = postgres(APP, { max: 2 });
    const drivers = { pg: rowstile(p), "postgres.js": postgresAuthz(sql), "Drizzle on pg": withAuthz(drizzle(p)),
                      "Drizzle on postgres.js": withAuthz(drizzlePostgres(sql)) };
    try {
      for (const [name, a] of Object.entries(drivers)) {
        expect(await actingAs("3", () => a.permsOf("project", [1, 3])), name).toEqual({ "1": ["edit", "view"], "3": ["view"] });
        expect(await actingAs("3", () => a.permsOf("project", [[1]])), name).toEqual({ "1": ["edit", "view"] });   // a key of one column, as an array
        expect(await actingAs("3", () => a.permsOf("project", [])), name).toEqual({});
        expect(await actingAs("3", () => a.list("project", "view")), name).toEqual(["1", "3"]);
        expect(await actingAs("3", () => a.can("project", [1], "edit")), name).toBe(true);
        expect((await actingAs("3", () => a.explainRule("app.notes", "update", 1)))?.[0], name).toMatch(/^no/);
        await a.check();
      }
    } finally {
      await p.end();
      await sql.end();
    }
  });

  // an UPDATE that matched nothing though the user may change the row isn't a refusal; a table named without
  // its schema is found on the search_path; a 42501 that isn't a policy's stays the driver's error
  test("refused means the database said no", async () => {
    const p = new pg.Pool({ connectionString: APP, options: "-c search_path=app" });
    const a = rowstile(p);
    try {
      await expect(actingAs("3", () => a.transaction(async (c) =>             // cy may edit note 4
        calls(c).expect(await c.query("UPDATE app.notes SET body = 'x' WHERE id = 4 AND body = 'something else'"), "app.notes", "update", 4))))
        .rejects.toBeNotFound();
      await expect(actingAs("3", () => db.note.update({ where: { id: 4, body: "something else" }, data: { body: "x" } })))
        .rejects.toBeNotFound();
      await expect(actingAs("3", () => a.transaction(async (c) =>
        calls(c).expect(await c.query("UPDATE notes SET body = 'x' WHERE id = 1"), "notes", "update", 1))))
        .rejects.toBeRefused("update", "note.edit");
      // ... and it is named as the policy names it, with its schema, as a refused insert is
      const bare = await actingAs("3", () => a.transaction(async (c) =>
        calls(c).expect(await c.query("UPDATE notes SET body = 'x' WHERE id = 1"), "notes", "update", 1))).catch((err) => err);
      expect([bare.table, bare.message]).toEqual(["app.notes", "permission denied: user 3 may not update row 1 of app.notes"]);
      expect(await actingAs("1", () => db.$authz.tableName("pg_class"))).toBe("pg_catalog.pg_class");
      expect(await actingAs("1", () => db.$authz.tableName("no_such_table"))).toBe("no_such_table");
      // a column's rule through a driver that drops the error's fields (Prisma's): the table and the command
      // from its words; and the database's own code for a refusal that isn't a rule's
      const column = refusal(Object.assign(new Error("changing locked of app.notes 7 needs: folder.manage"),
        { code: "42501", hint: "rowstile help AZ709" }));
      expect([column?.table, column?.command, column?.code]).toEqual(["app.notes", "update", "AZ709"]);
      const share = refusal(Object.assign(new Error("you cannot share project 1"), { code: "42501", hint: "rowstile help AZ705" }));
      expect([share?.table, share?.command, share?.code]).toEqual([undefined, undefined, "AZ705"]);
      const e = await actingAs("1", () => a.query("SELECT * FROM public._prisma_migrations")).catch((err) => err);
      expect(sqlstate(e)).toBe("42501");
      expect(translate(e)).toBeNull();
      // an upsert whose existing row the user may not update: the update rule's doing, not the select rule's
      await expect(actingAs("3", () => db.note.upsert({ where: { id: 1 }, update: { body: "x" },
        create: { id: 1, project_id: 1, author_id: 3, body: "x" } }))).rejects.toBeRefused("update");
      expect(sqlstate(Object.assign(new Error("write EPIPE"), { code: "EPIPE" }))).toBeUndefined();
    } finally {
      await p.end();
    }
  });

  // a transaction told who it acts for runs the hooks before signing in too (@rowstile/next's cache guard is one)
  test("the sign-in hooks run for a transaction given who", async () => {
    const seen: (string | null)[] = [];
    beforeSignIn((who) => { seen.push(who.id); });
    const p = new pg.Pool({ connectionString: APP });
    const sql = postgres(APP, { max: 1 });
    try {
      await rowstile(p).transaction((c) => c.query("SELECT 1"), "2");
      await postgresAuthz(sql).begin((tx) => tx`SELECT 1`, "3");
      await withAuthz(drizzle(p)).transaction((tx) => tx.execute(sqlTag`SELECT 1`), ["service", 1]);
      await rowstile(p).transaction((c) => c.query("SELECT 1"), null);
      expect(seen).toEqual(["2", "3", "1", null]);
    } finally {
      await p.end();
      await sql.end();
    }
  });

  // Inside transaction(fn, who), the object's own calls run in that transaction: as who, not as whoever the code
  // around it acts for; they see what it wrote; and on a pool of one they wait for no second connection. (Code in
  // fn that acts for someone else is refused: the next check.)
  test("inside a transaction, the object's own calls run in it, as who it signed in as", async () => {
    const p = new pg.Pool({ connectionString: APP, max: 1, connectionTimeoutMillis: 2000 });
    const sql = postgres(APP, { max: 1 });
    const NEW = "INSERT INTO app.notes (project_id, author_id, body) VALUES (1, 3, 'new') RETURNING id";
    // bo (2) acts around it; the transaction signs in as cy (3), who writes a note bo can't see: cy may edit it
    const asked = (a: Pick<AuthzCalls, "can">, id: number) => Promise.all([current()?.id, a.can("note", id, "edit")]);
    try {
      const pgA = rowstile(p);
      expect(await actingAs("2", () => pgA.transaction(async (c) => {
        const id = (await c.query(NEW)).rows[0].id;
        return [...await asked(pgA, id), (await pgA.query("SELECT count(*)::int AS n FROM app.notes WHERE id = $1", [id])).rows[0].n];
      }, "3"))).toEqual(["3", true, 1]);
      const pgExpect = await actingAs("2", () => pgA.transaction(async (c) =>
        pgA.expect(await c.query("UPDATE app.notes SET body = 'x' WHERE id = 1"), "app.notes", "update", 1), "3")).catch((e) => e);
      expect(pgExpect.message).toBe("permission denied: user 3 may not update row 1 of app.notes");
      const postgresA = postgresAuthz(sql);
      expect(await actingAs("2", () => postgresA.begin(async (tx) =>
        asked(postgresA, (await tx.unsafe(NEW))[0].id), "3"))).toEqual(["3", true]);
      const onPg = withAuthz(drizzle(p));
      expect(await actingAs("2", () => onPg.transaction(async (tx) =>
        asked(onPg, (await drizzleQueryable(tx).query(NEW)).rows[0].id), "3"))).toEqual(["3", true]);
      const onPostgres = withAuthz(drizzlePostgres(sql));
      expect(await actingAs("2", () => onPostgres.transaction(async (tx) =>
        asked(onPostgres, (await drizzleQueryable(tx).query(NEW)).rows[0].id), "3"))).toEqual(["3", true]);
    } finally {
      await p.end();
      await sql.end();
    }
  });

  // A transaction is one principal's: a sign-in lasts the database transaction. Inside one, the object's work for
  // anyone else (a user, a service, nobody) throws at once, before anything is sent for it: on a pool of one, a
  // second connection would wait until the pool's timeout. The transaction goes on as its own principal, and commits.
  test("a transaction is one principal's: another's work inside it is refused, and it goes on as its own", async () => {
    const p = new pg.Pool({ connectionString: APP, max: 1, connectionTimeoutMillis: 2000 });
    const sql = postgres(APP, { max: 1 });
    const said = (who: string) => "this transaction is signed in as user 1 already, and a sign-in lasts the database " +
      `transaction: ${who}'s work can't run inside it. Run it after, or in a transaction of its own (another connection)`;
    const refused = (work: () => Promise<unknown>) => work().then(() => "it ran", (e: Error) => `${e.constructor.name}: ${e.message}`);
    const ME = "SELECT current_setting('authz.user_id') AS x";
    const KEPT = "UPDATE app.notes SET body = 'still ann''s' WHERE id = 1 RETURNING id AS x";
    const ran: string[] = [];
    // inside ann's (1) transaction: bo's (2) question, a service's transaction, nobody's question; then ann's own
    const inside = async (a: Pick<AuthzCalls, "can">, begin: (fn: () => Promise<unknown>, who: [string, number]) => Promise<unknown>,
                          q: (text: string) => Promise<{ x: unknown }[]>) => [
      await refused(() => actingAs("2", () => a.can("project", 2, "edit"))),
      await refused(() => begin(async () => ran.push("inner"), ["service", 1])),
      await refused(() => actingAs(null, () => a.can("project", 3, "view"))),
      (await q(ME))[0].x, (await q(KEPT))[0].x, await a.can("note", 1, "edit"),
    ];
    const expected = ["Error: " + said("user 2"), "Error: " + said("service 1"), "Error: " + said("nobody"), "1", 1, true];
    try {
      const pgA = rowstile(p);
      expect(await actingAs("1", () => pgA.transaction(async (c) => [
        await refused(() => actingAs("2", () => pgA.query("INSERT INTO app.notes (project_id, author_id, body) VALUES (2, 2, 'bo''s')"))),
        ...await inside(pgA, (fn, who) => pgA.transaction(fn, who), async (t) => (await c.query(t)).rows),
      ]))).toEqual(["Error: " + said("user 2"), ...expected]);
      const postgresA = postgresAuthz(sql);
      expect(await actingAs("1", () => postgresA.begin((tx) =>
        inside(postgresA, (fn, who) => postgresA.begin(fn, who), async (t) => [...await tx.unsafe<{ x: unknown }[]>(t)])))).toEqual(expected);
      const onPg = withAuthz(drizzle(p));
      expect(await actingAs("1", () => onPg.transaction((tx) =>
        inside(onPg, (fn, who) => onPg.transaction(fn, who), async (t) => (await drizzleQueryable(tx).query(t)).rows)))).toEqual(expected);
      const onPostgres = withAuthz(drizzlePostgres(sql));
      expect(await actingAs("1", () => onPostgres.transaction((tx) =>
        inside(onPostgres, (fn, who) => onPostgres.transaction(fn, who), async (t) => (await drizzleQueryable(tx).query(t)).rows)))).toEqual(expected);
      expect(ran).toEqual([]);
      // what each transaction wrote was committed; bo's insert was never sent
      expect((await actingAs("2", () => pgA.query("SELECT count(*)::int AS n FROM app.notes WHERE body = 'bo''s'"))).rows[0].n).toBe(0);
      expect((await actingAs("1", () => pgA.query("SELECT body FROM app.notes WHERE id = 1"))).rows[0].body).toBe("still ann's");
    } finally {
      await p.end();
      await sql.end();
    }
  });

  // Work fn starts and doesn't await (a promise left running, a timer) may run after the transaction has ended, when
  // its connection serves another request's transaction: it asks in a transaction of its own, as whoever it acts for,
  // someone else too (the transaction it was started in is over: nothing to refuse). On a pool of one, bo's late call
  // is made while ann's transaction holds the connection
  test("work a transaction started, run after it ended, runs in a transaction of its own", async () => {
    const p = new pg.Pool({ connectionString: APP, max: 1 });
    const sql = postgres(APP, { max: 1 });
    const pause = "SELECT pg_sleep(0.3)";
    type Driver = { list: AuthzCalls["list"]; run: (fn: (pause: () => Promise<unknown>) => Promise<void>) => Promise<void> };
    const onPg = withAuthz(drizzle(p));
    const onPostgres = withAuthz(drizzlePostgres(sql));
    const pgA = rowstile(p);
    const postgresA = postgresAuthz(sql);
    const drivers: Record<string, Driver> = {
      pg: { list: pgA.list, run: (fn) => pgA.transaction((c) => fn(() => c.query(pause))) },
      "postgres.js": { list: postgresA.list, run: (fn) => postgresA.begin((tx) => fn(() => tx.unsafe(pause))) },
      "Drizzle on pg": { list: onPg.list, run: (fn) => onPg.transaction((tx) => fn(() => tx.execute(sqlTag.raw(pause)))) },
      "Drizzle on postgres.js": {
        list: onPostgres.list, run: (fn) => onPostgres.transaction((tx) => fn(() => tx.execute(sqlTag.raw(pause)))),
      },
    };
    const answered: Record<string, string[][]> = {};
    try {
      for (const [name, d] of Object.entries(drivers)) {
        let go!: () => void;
        const gate = new Promise<void>((r) => { go = r; });
        let later!: Promise<string[][]>;
        await actingAs("2", () => d.run(async () => {
          // bo's, made once ann's transaction holds the connection; then cy's, from the same late work
          later = gate.then(async () => [await d.list("project", "view"), await actingAs("3", () => d.list("project", "view"))]);
        }));
        await actingAs("1", () => d.run(async (pause) => {
          go();
          await pause();
        }));
        answered[name] = await later;
      }
      expect(answered).toEqual(Object.fromEntries(Object.keys(drivers).map((name) => [name, [["2", "3"], ["1", "3"]]])));
    } finally {
      await p.end();
      await sql.end();
    }
  });

  // a connection that drops while a transaction holds it fails that transaction, not the process; the next works
  test("pg and Drizzle on pg: a connection lost inside a transaction", async () => {
    const p = new pg.Pool({ connectionString: APP, max: 1 });
    const owner = new pg.Client({ connectionString: OWNER });
    await owner.connect();
    const a = rowstile(p);
    const d = withAuthz(drizzle(p));
    const lose = async (pid: number) => {
      await owner.query("SELECT pg_terminate_backend($1)", [pid]);
      await new Promise((r) => setTimeout(r, 300));                 // the app awaits something else meanwhile
    };
    try {
      await expect(actingAs("1", () => a.transaction(async (c) => {
        await lose((await c.query("SELECT pg_backend_pid() AS pid")).rows[0].pid);
        return c.query("SELECT 1");
      }))).rejects.toThrow();
      expect(await actingAs("2", () => a.list("project", "view"))).toEqual(["2", "3"]);
      await expect(actingAs("1", () => d.transaction(async (tx) => {
        await lose((await tx.execute(sqlTag`SELECT pg_backend_pid() AS pid`)).rows[0].pid as number);
        return tx.execute(sqlTag`SELECT 1`);
      }))).rejects.toThrow();
      expect(await actingAs("2", () => d.list("project", "view"))).toEqual(["2", "3"]);
    } finally {
      await owner.end();
      await p.end();
    }
  });

  // the change feed says so once when it begins to listen, and again after its connection drops
  test("pg: changes() after its connection is lost", async () => {
    const feedPool = new pg.Pool({ connectionString: FEED, max: 1 });
    feedPool.on("error", () => undefined);
    const owner = new pg.Client({ connectionString: OWNER });
    await owner.connect();
    const a = rowstile(pool);
    let seen = 0;
    const stop = changes(feedPool)(() => { seen++; });
    const until = async (ok: () => boolean) => { for (let i = 0; i < 100 && !ok(); i++) await new Promise((r) => setTimeout(r, 100)); };
    try {
      await until(() => seen > 0);                                    // listening: told once, for what changed before
      expect(seen).toBe(1);
      await actingAs("1", () => a.share("project", 1, "viewer", "user", 2));
      await until(() => seen > 1);
      expect(seen).toBeGreaterThan(1);
      await owner.query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE query ILIKE 'LISTEN authz_changes%' AND pid <> pg_backend_pid()");
      seen = 0;
      await until(() => seen > 0);                                    // listening again: told once
      expect(seen).toBe(1);
      await actingAs("1", () => a.unshare("project", 1, "viewer", "user", 2));
      await until(() => seen > 1);
      expect(seen).toBeGreaterThan(1);
    } finally {
      stop();
      await owner.end();
      await new Promise((r) => setTimeout(r, 200));
      await feedPool.end();
    }
  });

  test("Drizzle: inIds on a key with a length", () => {
    const t = pgSchema("app").table("t", { a: varchar("a", { length: 30 }), b: numeric("b", { precision: 10, scale: 0 }) });
    expect(() => inIds(t.a, "project", "edit")).not.toThrow();
    expect(() => inIds(t.b, "project", "edit")).not.toThrow();
    expect(() => drizzleIds("project", "edit", "text); DROP TABLE x; --")).toThrow("not a type name");
  });
});

// the routes the React kit calls take JSON only (a form on another site can't send it), and a long list of ids
// goes in a body
test("authzRoutes: POST takes application/json only; perms for a long list", async () => {
  const body = JSON.stringify({ type: "project", id: "1", relation: "viewer", subjectType: "user", subjectId: "2" });
  const plain = await fetch(`${SERVER}/api/authz/share`, { method: "POST", headers: { "x-user": "1", "content-type": "text/plain" }, body });
  expect(plain.status).toBe(415);
  expect(await (await fetch(`${SERVER}/api/projects`, as("2"))).json()).toEqual([2, 3]);     // nothing was shared
  const perms = await fetch(`${SERVER}/api/authz/perms`, as("3", { method: "POST", body: JSON.stringify({ type: "project", ids: ["1", "3"] }) }));
  expect(await perms.json()).toEqual({ "1": ["edit", "view"], "3": ["view"] });
});

// each open event stream holds a subscriber: their number has a limit, and a closed one frees its place
test("authzRoutes: no more event streams than maxStreams", async () => {
  let subscribers = 0;
  const { GET } = authzRoutes({ calls: db.$authz, maxStreams: 2, changes: () => { subscribers += 1; return () => { subscribers -= 1; }; } });
  const open = () => {
    const controller = new AbortController();
    return { controller, response: GET(new Request("http://app.test/api/authz/events", { signal: controller.signal })) };
  };
  const [one, two] = [open(), open()];
  expect([(await one.response).status, (await two.response).status]).toEqual([200, 200]);
  expect((await open().response).status).toBe(503);
  expect(subscribers).toBe(2);
  one.controller.abort();
  expect(subscribers).toBe(1);
  expect((await open().response).status).toBe(200);
});

// 14: after a policy change and a new migration, the app works with the new generated names
test("14: a policy change ships as the next migration", () => {
  const work = join(HERE, ".work", "check14");
  rmSync(work, { recursive: true, force: true });
  for (const part of ["db", "prisma", "rowstile.toml", "prisma.config.ts"]) cpSync(join(HERE, part), join(work, part), { recursive: true });
  const policy = join(work, "db", "policy.authz");
  writeFileSync(policy, readFileSync(policy, "utf8").replace("  can read = recipient\n", "  can read = recipient\n  can reply = recipient\n"));
  const env = { ...process.env };
  execFileSync(PYTHON, [CLI, "migrate", "--name", "reply"], { cwd: work, stdio: "pipe", env });
  const deploy = run("prisma", ["migrate", "deploy"], work);
  expect(deploy.status, deploy.stdout + deploy.stderr).toBe(0);
  execFileSync(PYTHON, [CLI, "client"], { cwd: work, stdio: "pipe", env });
  const names = readFileSync(join(work, "src", "authz.gen.ts"), "utf8");
  expect(names).toContain('"reply"');
  writeFileSync(join(work, "use.ts"), 'import "./src/authz.gen.ts";\nimport type { Permission } from "@rowstile/client";\n' +
    'export const p: Permission<"message"> = "reply";\n');
  writeFileSync(join(work, "tsconfig.json"), JSON.stringify({ extends: "../../tsconfig.json", compilerOptions: { incremental: false, plugins: [] }, exclude: [], include: ["use.ts", "src/authz.gen.ts"] }));
  const tsc = run("tsc", ["-p", "tsconfig.json", "--noEmit"], work);
  expect(tsc.status, tsc.stdout).toBe(0);
});

test("14: ... and the running app has the new permission", async () => {
  const inbox = await actingAs("1", () => db.$executeRaw`INSERT INTO app.inbox (sender_id, recipient_id, body) VALUES (1, 2, 'hi')`);
  expect(inbox).toBe(1);
  const perms = await actingAs("2", async () => {
    const [m] = await db.message.findMany({ where: { recipient_id: 2 } });
    return db.$authz.perms("message", m.id);
  });
  expect(perms).toContain("reply");
  expect(current()).toBeUndefined();
});

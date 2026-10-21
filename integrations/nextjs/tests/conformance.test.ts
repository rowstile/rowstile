// The conformance suite (integrations/README.md): the same checks for every stack. This is Next.js
// (App Router), Prisma 7 on node-postgres, Prisma Migrate; then pg, postgres.js and Drizzle without Prisma.
// test.sh does check 11 (a fresh database: migrate, the policy's tests, then Prisma's own diff shows no
// change) and starts the servers these checks call, before they run.
import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
import { idShown, Refused, refusal, verdict } from "@rowstile/client";
import { describe as describePrincipal, parsePrincipal, principal } from "@rowstile/client";
import { authzRoutes } from "@rowstile/next";
import { authz as rowstile } from "@rowstile/pg";
import { calls, changes } from "@rowstile/pg";
import { authz as postgresAuthz } from "@rowstile/postgres";
import { expect as drizzleExpect, inIds, withAuthz } from "@rowstile/drizzle";
import { ids as drizzleIds } from "@rowstile/drizzle";
import { databasePerWorker } from "@rowstile/vitest";
import { PrismaPg } from "@prisma/adapter-pg";
import { authz, signedIn } from "@rowstile/prisma";
import { PrismaClient } from "@/generated/prisma/client.ts";
import { db, pool } from "@/db";
import { digest } from "@/jobs";
import { renameNote } from "../app/actions";
import { APP, EXPECTED, FEED, OWNER, SERVER, SERVER_ONE, as, seed } from "./data";

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

// 3: not signed in at all: the strict sign-in error, naming act_as
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
  // a page that caches what the user may see fails, instead of serving it to the next user
  const cached = await fetch(`${SERVER}/cached-notes`, as("1"));
  expect(cached.status).toBe(500);
  const other = await fetch(`${SERVER}/cached-notes`, as("2"));
  expect(ids(await other.text())).not.toEqual(EXPECTED["1"]);
  // the same with the "use cache" directive: the page whose user comes from the request, and the one whose
  // user is known without it (only @rowstile/next's connection() stops that one)
  for (const page of ["use-cache-notes", "use-cache-known-user"]) {
    for (const user of ["1", "2", "1"]) {
      const r = await fetch(`${SERVER}/${page}`, as(user));
      expect(r.status, `${page} as ${user}`).toBe(500);
      expect(ids(await r.text()), `${page} as ${user}`).toEqual([]);
    }
  }
});

// server actions: a refusal comes back as a problem, not a hidden error
test("server actions answer with the problem", async () => {
  expect(await actingAs("3", () => renameNote(4, "mine"))).toEqual({ ok: true, value: 4 });
  const refused = await actingAs("3", () => renameNote(1, "x"));
  expect(refused.ok).toBe(false);
  expect(!refused.ok && refused.problem.status).toBe(403);
  const hidden = await actingAs("2", () => renameNote(1, "x"));
  expect(!hidden.ok && hidden.problem.status).toBe(404);
});

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
      await expect(a.begin(async (tx) => tx`DELETE FROM app.notes WHERE id = 1 RETURNING id`.then((rows) =>
        a.expect(rows, "app.notes", "delete", 1)), "2")).rejects.toBeNotFound();
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

  // a connection that drops while a transaction holds it fails that transaction, not the process; the next works
  test("pg: a connection lost inside a transaction", async () => {
    const p = new pg.Pool({ connectionString: APP, max: 1 });
    const owner = new pg.Client({ connectionString: OWNER });
    await owner.connect();
    const a = rowstile(p);
    try {
      await expect(actingAs("1", () => a.transaction(async (c) => {
        const pid = (await c.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
        await owner.query("SELECT pg_terminate_backend($1)", [pid]);
        await new Promise((r) => setTimeout(r, 300));               // the app awaits something else meanwhile
        return c.query("SELECT 1");
      }))).rejects.toThrow();
      expect(await actingAs("2", () => a.list("project", "view"))).toEqual(["2", "3"]);
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

// Neon's serverless driver (preview): its Pool talks to Postgres over WebSockets, here through Neon's wsproxy in
// front of the suite's Postgres (test.sh), with @rowstile/pg. Checks 1, 2, 4, 5, 6 and 7 through it: on the
// Node.js runtime (app/api/neon, one pool for the server, a pool of one on SERVER_ONE), on the edge runtime
// (edge/, an app of its own: a pool for each request), and in this process. With POOLER=pgbouncer the proxy goes through
// PgBouncer, as Neon's pooled URL does.
import { spawnSync } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Pool } from "@neondatabase/serverless";
import { afterAll, beforeEach, expect, test } from "vitest";
import { actingAs } from "@rowstile/client";
import { authz } from "@rowstile/pg";
import { neon, neonPool } from "@/neon";
import { EXPECTED, SERVER, SERVER_EDGE, SERVER_ONE, as, seed } from "./data";

const HERE = dirname(dirname(fileURLToPath(import.meta.url)));
const TSC = join(HERE, "..", "..", "node_modules", "typescript", "bin", "tsc");
const NEON = process.env.ROWSTILE_NEON_URL ?? "";

beforeEach(seed);
afterAll(() => neonPool.end());

// the notes, as each runtime's routes answer them
const runtimes = { node: `${SERVER}/api/neon/notes`, edge: `${SERVER_EDGE}/api/notes` };

test("1, 2 (Neon): lists show what each may see, on either runtime", async () => {
  expect(NEON, "ROWSTILE_NEON_URL (test.sh sets it)").toBeTruthy();
  for (const path of Object.values(runtimes)) {
    for (const [user, notes] of Object.entries(EXPECTED)) {
      const r = await fetch(path, as(user || null));
      expect([path, r.status, await r.json()], user).toEqual([path, 200, notes]);
    }
  }
  for (const [user, notes] of Object.entries(EXPECTED)) {
    const { rows } = await actingAs(user || null, () => neon.query("SELECT id FROM app.notes ORDER BY id"));
    expect(rows.map((r) => r.id), user).toEqual(notes);
  }
});

test("4 (Neon): a pooled connection carries no one over", async () => {
  for (const user of ["1", "2", "", "3", "2"]) {
    expect(await (await fetch(`${SERVER_ONE}/api/neon/notes`, as(user || null))).json(), user).toEqual(EXPECTED[user]);
  }
  const one = new Pool({ connectionString: NEON, max: 1 });
  const a = authz(one);
  try {
    for (const user of ["1", "2", "", "3", "2"]) {
      const ids = await a.transaction(async (c) => (await c.query("SELECT id FROM app.notes ORDER BY id")).rows.map((r) => r.id), user || null);
      expect(ids, user).toEqual(EXPECTED[user]);
    }
  } finally {
    await one.end();
  }
});

test("5 (Neon): concurrent requests never mix users", async () => {
  const users = Array.from({ length: 40 }, (_, i) => ["1", "2", "3", ""][i % 4]);
  for (const path of [runtimes.node, `${SERVER_ONE}/api/neon/notes`, runtimes.edge]) {
    const got = await Promise.all(users.map((u) => fetch(path, as(u || null)).then((r) => r.json())));
    expect(got, path).toEqual(users.map((u) => EXPECTED[u]));
  }
  const here = await Promise.all(users.map((u) => actingAs(u || null, () => neon.query("SELECT id FROM app.notes ORDER BY id"))));
  expect(here.map((r) => r.rows.map((n) => n.id))).toEqual(users.map((u) => EXPECTED[u]));
});

test("6 (Neon): a refused insert says which rule, on either runtime", async () => {
  for (const path of Object.values(runtimes)) {
    const r = await fetch(path, as("2", { method: "POST", body: JSON.stringify({ project_id: 3, body: "hi" }) }));
    expect([path, r.status, r.headers.get("content-type")]).toEqual([path, 403, "application/problem+json"]);
    const body = await r.json();
    expect([body.table, body.command, body.code]).toEqual(["app.notes", "insert", "AZ709"]);
    expect(body.detail).toContain("user 2 may not insert this row into app.notes");
    expect(body.why.some((line: string) => line.includes("project.edit"))).toBe(true);
    const mine = await fetch(path, as("1", { method: "POST", body: JSON.stringify({ project_id: 1, body: "ok" }) }));
    expect([path, mine.status]).toEqual([path, 201]);
  }
  await expect(actingAs("2", () => neon.query("INSERT INTO app.notes (project_id, author_id, body) VALUES (3, 2, 'hi')")))
    .rejects.toBeRefused("insert", "project.edit");
});

test("7 (Neon): hidden is 404, not allowed is 403, on either runtime", async () => {
  for (const path of Object.values(runtimes)) {
    const patch = (id: number, user: string) =>
      fetch(`${path}/${id}`, as(user, { method: "PATCH", body: JSON.stringify({ body: "x" }) }));
    const hidden = await patch(1, "2");
    const refused = await patch(1, "3");
    const mine = await patch(4, "3");
    expect([path, hidden.status, refused.status, mine.status]).toEqual([path, 404, 403, 200]);
    const why = await refused.json();
    expect([why.command, why.code, why.detail]).toEqual(["update", "AZ709", "permission denied: user 3 may not update row 1 of app.notes"]);
    expect(why.why.some((line: string) => line.includes("edit"))).toBe(true);
  }
  const gone = await fetch(`${runtimes.node}/2`, as("1", { method: "DELETE" }));
  const no = await fetch(`${runtimes.node}/1`, as("3", { method: "DELETE" }));
  const done = await fetch(`${runtimes.node}/4`, as("3", { method: "DELETE" }));
  expect([gone.status, no.status, done.status]).toEqual([404, 403, 204]);
  expect((await no.json()).detail).toBe("permission denied: user 3 may not delete row 1 of app.notes");
});

test("edge: what has no edge runtime says so (checkAtStart)", async () => {
  const r = await fetch(`${SERVER_EDGE}/api/check`);
  expect((await r.json()).said).toContain('call it in register() where NEXT_RUNTIME is "nodejs"');
});

// 9, for the pool: Neon's type-checks with @rowstile/pg, its transactions get Neon's own client, and something that
// isn't a pool doesn't type-check
test("9 (Neon): a pool that works as pg's type-checks, and its client is its own", () => {
  const dir = join(HERE, ".work", "typecheck-neon");
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const check = (name: string, code: string) => {
    writeFileSync(join(dir, `${name}.ts`), code);
    writeFileSync(join(dir, `tsconfig.${name}.json`), JSON.stringify({
      extends: "../../tsconfig.json", compilerOptions: { incremental: false, plugins: [] }, exclude: [], include: [`${name}.ts`],
    }));
    return spawnSync(process.execPath, [TSC, "-p", `tsconfig.${name}.json`, "--noEmit"], { cwd: dir, encoding: "utf8" });
  };
  const head = 'import { Pool, type PoolClient } from "@neondatabase/serverless";\nimport pg from "pg";\nimport { authz, changes } from "@rowstile/pg";\n';
  const good = check("good", head +
    "const a = authz(new Pool({}));\nexport const own: Promise<PoolClient> = a.transaction(async (c) => c);\n" +
    "export const p: Promise<pg.PoolClient> = authz(new pg.Pool({})).transaction(async (c) => c);\n" +
    "export const feed = changes(new Pool({}));\nexport const pool: Pool = a.pool;\n");
  const bad = check("bad", head + "export const a = authz({ connect: async () => ({ rows: [] }) });\n");
  expect(good.status, good.stdout + good.stderr).toBe(0);
  expect(bad.status).not.toBe(0);
  expect(bad.stdout).toContain("ClientLike");
});

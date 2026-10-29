// @rowstile/jest: the matchers as Jest runs them, the worker's number, and a database per worker (check 12). This
// file runs on its own Jest worker beside tests/conformance.test.ts, in a copy of the test database of its own.
import { afterAll, beforeAll, describe, expect, test } from "@jest/globals";
import pg from "pg";
import { current, NotFound, Refused } from "@rowstile/client";
import { asUser, databasePerWorker, matchers, workerId } from "@rowstile/jest";
import { authz } from "@rowstile/pg";
import { APP, TESTS, appAt, owner, seed } from "./data.js";

const REFUSED = "permission denied: user 3 may not update row 1 of app.notes";

// 12: this worker's copy of the migrated test database: the policy is there, and what the tests write stays there
describe("12: a test database for this worker", () => {
  let worker: { url: string; appUrl?: string } = { url: "" };
  let p: pg.Pool;
  beforeAll(async () => {
    worker = await databasePerWorker(TESTS, { appUrl: appAt(TESTS) });
    await seed(worker.url);
    p = new pg.Pool({ connectionString: worker.appUrl });
  });
  afterAll(() => p.end());

  test("12: its own copy, with the policy", async () => {
    expect(worker.url.endsWith(`/conf_tests_w${process.env.JEST_WORKER_ID}`)).toBe(true);
    const a = authz(p);
    await a.check();
    await expect(asUser("2", () => a.query("INSERT INTO app.notes (project_id, author_id, body) VALUES (3, 2, 'hi')")))
      .rejects.toBeRefused("insert", "project.edit");
    await expect(asUser("3", () => a.transaction(async (c) =>
      a.expect(await c.query("UPDATE app.notes SET body = 'x' WHERE id = 1"), "app.notes", "update", 1))))
      .rejects.toBeRefused("update", "note.edit");
    await expect(asUser("2", () => a.transaction(async (c) =>
      a.expect(await c.query("DELETE FROM app.notes WHERE id = 1"), "app.notes", "delete", 1)))).rejects.toBeNotFound();
    // .not, and .resolves: what passes and what doesn't, either way
    await expect(asUser("1", () => a.query("SELECT 1"))).resolves.not.toBeRefused();
    expect(new Refused(REFUSED, "app.notes", "update", ["no   update : edit"])).not.toBeNotFound();
    expect(await asUser("3", () => a.list("project", "edit"))).toEqual(["1"]);
  });
});

describe("@rowstile/jest", () => {
  test("what the matchers say when a check fails", () => {
    const refused = new Refused(REFUSED, "app.notes", "update", ["no   update : edit"]);
    expect(matchers.toBeRefused(refused).message()).toBe(`expected the write not to be refused, but: ${REFUSED}`);
    expect(matchers.toBeRefused(refused, "delete").message()).toBe(`expected the delete rule to refuse it, but the update rule did: ${REFUSED}`);
    expect(matchers.toBeRefused(refused, "update", "project.edit").message())
      .toBe(`expected "project.edit" in the reason, got:\n${REFUSED}\nno   update : edit`);
    expect(matchers.toBeRefused(refused, "update", "update : edit").pass).toBe(true);   // the reason's lines count
    expect(matchers.toBeRefused(refused, "update", "user 3").pass).toBe(true);          // and its message
    expect(matchers.toBeRefused(new Error("boom")).message()).toBe("expected a refused write, got Error: boom");
    expect(matchers.toBeRefused({ rows: 1 }).message()).toBe('expected a refused write, got {"rows":1}');
    expect(matchers.toBeRefused(Symbol("nothing")).message()).toBe("expected a refused write, got Symbol(nothing)");
    expect(matchers.toBeNotFound(new NotFound("app.notes", "1")).message()).toBe("expected the row to be found, but: app.notes 1 not found");
    expect(matchers.toBeNotFound(refused).message()).toBe(`expected NotFound, got Refused: ${REFUSED}`);
    expect(asUser(3, () => current())).toEqual({ type: "user", id: "3" });
    // ... and as Jest reports them
    expect(() => expect(refused).toBeRefused("delete")).toThrow("expected the delete rule to refuse it");
    expect(() => expect(refused).toBeNotFound()).toThrow("expected NotFound, got Refused");
  });

  test("the worker's number, from Jest's variable (or Vitest's)", () => {
    const saved = { ...process.env };
    try {
      delete process.env.VITEST_POOL_ID;
      delete process.env.VITEST_WORKER_ID;
      process.env.JEST_WORKER_ID = "4";
      expect(workerId()).toBe("4");
      process.env.VITEST_WORKER_ID = "7";
      expect(workerId()).toBe("7");
      process.env.VITEST_POOL_ID = "9";
      expect(workerId()).toBe("9");
      delete process.env.VITEST_POOL_ID;
      delete process.env.VITEST_WORKER_ID;
      delete process.env.JEST_WORKER_ID;
      expect(workerId()).toBe("1");
    } finally {
      process.env = saved;
    }
  });

  // on a database of its own made from the test database (conf_hold), so that the connection held to it doesn't
  // stop the other worker copying the test database
  test("a database per worker: kept, copied again, and why it can't be copied", async () => {
    const hold = new URL(TESTS);
    hold.pathname = "/conf_hold";
    await owner(async (c) => {
      await c.query("DROP DATABASE IF EXISTS conf_hold WITH (FORCE)");
      await c.query("CREATE DATABASE conf_hold TEMPLATE conf_tests");
    }, new URL("/postgres", TESTS).toString());
    const saved = process.env.JEST_WORKER_ID;
    process.env.JEST_WORKER_ID = "8";
    try {
      const copy = await databasePerWorker(hold.toString());
      expect([copy.url.endsWith("/conf_hold_w8"), copy.appUrl]).toEqual([true, undefined]);
      await owner((c) => c.query("INSERT INTO app.users VALUES (1, 'ann')"), copy.url);
      const users = () => owner(async (c) => (await c.query<{ n: number }>("SELECT count(*)::int AS n FROM app.users")).rows[0]?.n, copy.url);
      expect((await databasePerWorker(hold.toString(), { fresh: false })).url).toBe(copy.url);
      expect(await users()).toBe(1);                                         // kept, with what was written
      await databasePerWorker(hold.toString());
      expect(await users()).toBe(0);                                         // copied again: as migrated
      const holding = new pg.Client({ connectionString: hold.toString() }); // something connected to the original
      await holding.connect();
      try {
        await expect(databasePerWorker(hold.toString())).rejects.toThrow("can't be copied while anything is connected to it");
      } finally {
        await holding.end();
      }
      // the database's own errors: a role that may not create databases, an original that isn't there
      await expect(databasePerWorker(appAt(hold.toString()))).rejects.toMatchObject({ code: "42501" });
      const gone = new URL(hold);
      gone.pathname += "_gone";
      await expect(databasePerWorker(gone.toString())).rejects.toMatchObject({ code: "3D000" });
      expect(APP).not.toBe("");
    } finally {
      process.env.JEST_WORKER_ID = saved;
      await owner((c) => c.query("DROP DATABASE IF EXISTS conf_hold_w8 WITH (FORCE)").then(() =>
        c.query("DROP DATABASE IF EXISTS conf_hold WITH (FORCE)")), new URL("/postgres", TESTS).toString());
    }
  });
});

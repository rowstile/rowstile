// The package at run time, with each Vitest it supports: types.sh runs this file with each one. No database: the
// errors are made here, as the drivers' packages make them.
import { expect, test } from "vitest";
import { current, NotFound, Refused } from "@rowstile/client";
import { asUser, matchers, workerId } from "@rowstile/vitest";

expect.extend(matchers);

test("the matchers", async () => {
  const refused = new Refused("the update rule refused it", "app.folders", "update", ["folder.edit: no"]);
  expect(refused).toBeRefused();
  expect(refused).toBeRefused("update", "folder.edit");
  expect(refused).not.toBeRefused("delete");
  expect(refused).not.toBeNotFound();
  await expect(Promise.reject(new NotFound("app.folders", "7"))).rejects.toBeNotFound();
  await expect(Promise.reject(refused)).rejects.toBeRefused("update");
  expect(() => expect(new Error("boom")).toBeRefused()).toThrow("expected a refused write, got Error: boom");
  expect(() => expect(refused).toBeNotFound()).toThrow("expected NotFound, got Refused: the update rule refused it");
});

test("asUser, and the worker's number", async () => {
  expect(await asUser("2", async () => current())).toEqual({ type: "user", id: "2" });
  // this Vitest still names the worker where workerId() reads it
  const pool = process.env.VITEST_POOL_ID;
  expect(pool).toMatch(/^\d+$/);
  expect(workerId()).toBe(pool);
  process.env.VITEST_POOL_ID = "7";
  try {
    expect(workerId()).toBe("7");
  } finally {
    process.env.VITEST_POOL_ID = pool;
  }
});

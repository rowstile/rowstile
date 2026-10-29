/**
 * rowstile with Jest (a preview: it may change in any release).
 *
 *     // tests/setup.ts (setupFilesAfterEnv)
 *     import { expect } from "@jest/globals";
 *     import { matchers } from "@rowstile/jest";
 *     expect.extend(matchers);
 *
 *     await expect(asUser(bob, () => rename(f.id, "x"))).rejects.toBeRefused("update", "folder.edit");
 *     await expect(asUser(bob, () => rename(hidden, "x"))).rejects.toBeNotFound();
 *
 * A database per worker: databasePerWorker(ownerUrl) copies the migrated test database (with the policy) once
 * for each Jest worker (JEST_WORKER_ID), so tests that write don't meet each other.
 *
 * The code is @rowstile/vitest's, which depends on no test framework; this package adds Jest's types for the
 * matchers.
 */
import type {} from "expect";

export { asUser, databasePerWorker, matchers, workerId } from "@rowstile/vitest/core";

// Jest's expect (the `expect` package, which @jest/globals' expect is) declares Matchers<R, T>: the same type
// parameters here, so the matchers return R, a promise after .resolves or .rejects
declare module "expect" {
  interface Matchers<R extends void | Promise<void>, T = unknown> {
    toBeRefused(command?: string, reason?: string): R;
    toBeNotFound(): R;
  }
}

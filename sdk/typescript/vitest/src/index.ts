/**
 * rowstile with Vitest (Jest: @rowstile/jest, which shares this package's core).
 *
 *     // vitest.setup.ts
 *     import { expect } from "vitest";
 *     import { matchers } from "@rowstile/vitest";
 *     expect.extend(matchers);
 *
 *     await expect(asUser(bob, () => rename(f.id, "x"))).rejects.toBeRefused("update", "folder.edit");
 *     await expect(asUser(bob, () => rename(hidden, "x"))).rejects.toBeNotFound();
 *
 * A database per worker: databasePerWorker(ownerUrl) copies the migrated test database (with the policy) once
 * for each worker, so tests that write don't meet each other.
 */
import type {} from "vitest";

export { asUser, databasePerWorker, matchers, workerId } from "./core.js";

// Vitest 4 declares Matchers<T = any>, Vitest 5 Matchers<R extends void | Promise<void> = ..., T = unknown>: a
// declaration without type parameters merges with either (every one has a default), so its matchers can't
// return Vitest's R. They return what R is in either: nothing, or a promise (after .resolves or .rejects).
declare module "vitest" {
  interface Matchers {
    toBeRefused(command?: string, reason?: string): void | Promise<void>;
    toBeNotFound(): void | Promise<void>;
  }
}

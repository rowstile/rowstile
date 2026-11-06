// The sync index's worker (src/worker.ts, the same in each sync engine's app), on a connection whose runs fail (the
// app role may not call authz.sync_work()): a run that fails waits before the next, as long as between two runs, and
// a stop settles whoever waits for a run.
import { expect, test, vi } from "vitest";
import { syncWorker } from "../src/worker.js";
import { APP } from "./data.js";

test("the worker: a run that fails waits before the next, and a stop settles whoever waits for one", async () => {
  const failed = vi.spyOn(console, "error").mockImplementation(() => {});
  const worker = syncWorker(APP, 250);
  try {
    const waiting = worker.ran();                                // someone waits for a run: each one fails
    waiting.catch(() => undefined);                              // (awaited below)
    await new Promise((resolve) => setTimeout(resolve, 1000));
    expect(failed.mock.calls.length).toBeGreaterThan(1);
    expect(failed.mock.calls.length).toBeLessThanOrEqual(8);     // a run every 250 ms: not one after the other
    expect(String(failed.mock.calls[0]![0])).toMatch(/^authz\.sync_work\(\) failed, the next run works the changes in/);
    await worker.stop();
    await expect(waiting).rejects.toThrow("the sync worker stopped before its next run");
    await expect(worker.ran()).rejects.toThrow("the sync worker is stopped");
  } finally {
    await worker.stop();
    failed.mockRestore();
  }
});

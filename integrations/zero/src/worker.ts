// The sync index's worker, for a policy that says `sync after commit`: authz.sync_work() in a loop beside the app,
// as an operator runs it (pg_cron, or the app's own jobs, would do as well). It connects as an administrator, here
// the policy's owner: the app role can't call it. Each run works in every change committed when it starts; one that
// fails leaves them for the next, which waits as long as between two runs.
import pg from "pg";

export interface SyncWorker {
  /** Resolves after a run that started after the call ends: the index then holds every change committed before.
   *  Rejects once the loop is stopped, before such a run. */
  ran(): Promise<void>;
  /** Stops the loop once the run at work ends, and resolves then. */
  stop(): Promise<void>;
}

/** Starts the loop on url, a run every `every` milliseconds, and at once when someone waits for one. */
export function syncWorker(url: string, every = 50): SyncWorker {
  const pool = new pg.Pool({ connectionString: url, max: 1 });
  let stopped = false;
  let waiting: { resolve: () => void; reject: (e: Error) => void }[] = [];
  let wake = () => {};
  const loop = (async () => {
    while (!stopped) {
      const due = waiting;
      waiting = [];
      let failed = false;
      try {
        await pool.query("SELECT authz.sync_work()");
        for (const w of due) w.resolve();
      } catch (e) {
        failed = true;
        waiting.unshift(...due);                         // the changes wait for the next run, and so do they
        console.error(`authz.sync_work() failed, the next run works the changes in: ${String(e)}`);
      }
      // after a failure, the next run waits too (the database down, an apply holding its locks): no loop that spins
      if (!stopped && (failed || !waiting.length)) await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, every);
        wake = () => {
          if (failed && !stopped) return;                // a wait for a run doesn't cut it short; a stop does
          clearTimeout(timer);
          resolve();
        };
      });
    }
    for (const w of waiting) w.reject(new Error("the sync worker stopped before its next run"));
    waiting = [];
    await pool.end();
  })();
  return {
    ran: () => new Promise<void>((resolve, reject) => {
      if (stopped) {
        reject(new Error("the sync worker is stopped"));
        return;
      }
      waiting.push({ resolve, reject });
      wake();
    }),
    stop: async () => {
      stopped = true;
      wake();
      await loop;
    },
  };
}

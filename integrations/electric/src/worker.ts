// The sync index's worker, for a policy that says `sync after commit`: authz.sync_work() in a loop beside the app,
// as an operator runs it (pg_cron, or the app's own jobs, would do as well). It connects as an administrator, here
// the policy's owner: the app role can't call it. Each run works in every change committed when it starts; one that
// fails leaves them for the next.
import pg from "pg";

export interface SyncWorker {
  /** Resolves after a run that started after the call ends: the index then holds every change committed before. */
  ran(): Promise<void>;
  /** Stops the loop once the run at work ends, and resolves then. */
  stop(): Promise<void>;
}

/** Starts the loop on url, a run every `every` milliseconds, and at once when someone waits for one. */
export function syncWorker(url: string, every = 50): SyncWorker {
  const pool = new pg.Pool({ connectionString: url, max: 1 });
  let stopped = false;
  let waiting: (() => void)[] = [];
  let wake = () => {};
  const loop = (async () => {
    while (!stopped) {
      const due = waiting;
      waiting = [];
      try {
        await pool.query("SELECT authz.sync_work()");
        for (const resolve of due) resolve();
      } catch (e) {
        waiting.unshift(...due);                         // the changes wait for the next run, and so do they
        console.error(`authz.sync_work() failed, the next run works the changes in: ${String(e)}`);
      }
      if (!stopped && !waiting.length) await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, every);
        wake = () => { clearTimeout(timer); resolve(); };
      });
    }
    await pool.end();
  })();
  return {
    ran: () => new Promise<void>((resolve) => {
      waiting.push(resolve);
      wake();
    }),
    stop: async () => {
      stopped = true;
      wake();
      await loop;
    },
  };
}

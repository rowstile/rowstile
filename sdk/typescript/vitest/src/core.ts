/**
 * What @rowstile/vitest and @rowstile/jest share, and what depends on neither: the matchers (plain functions, for
 * expect.extend), asUser, the worker's number and a database per worker. Each package re-exports it, beside its
 * framework's types for the matchers.
 */
import { actingAs, translate, NotFound, Refused, type Who } from "@rowstile/client";

/** Runs fn acting for `who`: every transaction it begins signs in as them. */
export function asUser<R>(who: Who, fn: () => R): R {
  return actingAs(who, fn);
}

interface Result {
  pass: boolean;
  message: () => string;
}

/** The error as rowstile's, whichever driver raised it. */
const asAuthz = (received: unknown) => translate(received) ?? received;

export const matchers = {
  /** The write was refused; optionally by this command's rule ("update"), and with this in its reason ("folder.edit"). */
  toBeRefused(received: unknown, command?: string, reason?: string): Result {
    const e = asAuthz(received);
    if (!(e instanceof Refused)) {
      return { pass: false, message: () => `expected a refused write, got ${describe(received)}` };
    }
    if (command !== undefined && e.command !== command) {
      return { pass: false, message: () => `expected the ${command} rule to refuse it, but the ${e.command} rule did: ${e.message}` };
    }
    if (reason !== undefined && !e.message.includes(reason) && !e.why.some((line) => line.includes(reason))) {
      return { pass: false, message: () => `expected "${reason}" in the reason, got:\n${[e.message, ...e.why].join("\n")}` };
    }
    return { pass: true, message: () => `expected the write not to be refused, but: ${e.message}` };
  },
  /** The row isn't there for this user (hidden, or gone). */
  toBeNotFound(received: unknown): Result {
    const e = asAuthz(received);
    return e instanceof NotFound
      ? { pass: true, message: () => `expected the row to be found, but: ${e.message}` }
      : { pass: false, message: () => `expected NotFound, got ${describe(received)}` };
  },
};

function describe(x: unknown): string {
  if (x instanceof Error) return `${x.name}: ${x.message}`;
  return JSON.stringify(x) ?? String(x);
}

/** This worker's number: Vitest's VITEST_POOL_ID, Jest's JEST_WORKER_ID. */
export function workerId(): string {
  return process.env.VITEST_POOL_ID ?? process.env.VITEST_WORKER_ID ?? process.env.JEST_WORKER_ID ?? "1";
}

/** A database for this worker, copied from `url`'s (migrated, with the policy): its URL, with the same user.
 *  The copy is made once per run by a role that may create databases (the owner), while nothing else is
 *  connected to the original. appUrl: the app role's URL for the copy, if given. */
export async function databasePerWorker(url: string, options: { appUrl?: string; fresh?: boolean } = {}): Promise<{ url: string; appUrl?: string }> {
  const { default: pg } = await import("pg");
  const base = new URL(url);
  const template = decodeURIComponent(base.pathname.slice(1));
  const name = `${template}_w${workerId()}`;
  const admin = new pg.Client({ connectionString: url });
  await admin.connect();
  try {
    const exists = (await admin.query("SELECT 1 FROM pg_database WHERE datname = $1", [name])).rowCount;
    if (exists && options.fresh === false) {
      // keep it
    } else {
      const q = (s: string) => '"' + s.replace(/"/g, '""') + '"';
      if (exists) await admin.query(`DROP DATABASE ${q(name)} WITH (FORCE)`);
      // CREATE DATABASE ... TEMPLATE needs no one else connected to the original: this connection moves off it
      await admin.end();
      const other = new pg.Client({ connectionString: withDatabase(url, "postgres") });
      await other.connect();
      try {
        await other.query(`CREATE DATABASE ${q(name)} TEMPLATE ${q(template)}`);
      } catch (e) {
        // 55006: something is connected to the original (Postgres has waited five seconds for it to leave)
        if ((e as { code?: string }).code !== "55006") throw e;
        throw new Error(`databasePerWorker: ${template} can't be copied while anything is connected to it: close ` +
          "what holds it (the app, a migration tool, a console). Where the service keeps a connection of its own " +
          "for minutes after yours (Neon does), a copy per worker can't be made: use one test database, where " +
          "each test rolls back, or a branch for each run", { cause: e });
      } finally {
        await other.end();
      }
    }
  } finally {
    // (pg's end() resolves, on a client ended above too: no check can make it fail here, left out of the measure)
    await admin.end().catch(/* v8 ignore next */ () => undefined);
  }
  return { url: withDatabase(url, name), appUrl: options.appUrl ? withDatabase(options.appUrl, name) : undefined };
}

function withDatabase(url: string, db: string): string {
  const u = new URL(url);
  u.pathname = "/" + encodeURIComponent(db);
  return u.toString();
}

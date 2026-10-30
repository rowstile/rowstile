/**
 * rowstile with node-postgres (pg).
 *
 *     const db = authz(new Pool({ connectionString }), { user: async () => (await auth())?.user.id });
 *     await db.transaction(async (client) => client.query("UPDATE app.notes SET body = $1 WHERE id = $2", [b, id]));
 *     await db.query("SELECT * FROM app.notes");       // one statement, in its own signed-in transaction
 *
 * Every transaction signs in with authz.act_as() as whoever the code acts for (actingAs, a job), else user(),
 * else nobody. Nothing uses a session-level SET, so pools and poolers in transaction mode are safe. A refused write
 * throws Refused (with the rule and why), the not-signed-in error (AZ701) NotSignedIn.
 */
import type { QueryResult, QueryResultRow } from "pg";
import {
  actAs, calls, signingIn, transactionScope, translate,
  type Principal, type Queryable, type UserResolver, type Who,
} from "@rowstile/client";

/** What authz() uses of a client from the pool: pg's PoolClient, or one that works as it does. */
export interface ClientLike {
  query<T extends QueryResultRow = any>(text: string, values?: unknown[]): Promise<QueryResult<T>>;
  on(event: "error", listener: (e: Error) => void): unknown;
  removeListener(event: "error", listener: (e: Error) => void): unknown;
  release(err?: Error | boolean): void;
}

/** What changes() uses of its client: it listens, and hears the connection end. */
interface ListeningClient extends ClientLike {
  on(event: "error", listener: (e: Error) => void): unknown;
  on(event: "end", listener: () => void): unknown;
  on(event: "notification", listener: () => void): unknown;
  removeAllListeners(event: "notification" | "end" | "error"): unknown;
}

/** A pool: pg's Pool, or a driver's that works as it does (the Neon serverless driver's Pool, over WebSockets). */
export interface PoolLike<C extends ClientLike = ClientLike> {
  connect(): Promise<C>;
}

/** The client a pool's connect() gives (pg's PoolClient for pg's Pool, Neon's for Neon's): connect() has two
 *  overloads, a promise and a callback, and this reads both. */
type ClientOf<P> = P extends { connect: { (...a: any[]): infer A; (...a: any[]): infer B } }
  ? Extract<Awaited<A> | Awaited<B>, ClientLike> : ClientLike;

export interface Options {
  /** Who the request is, when nothing set it with actingAs. */
  user?: UserResolver;
}

async function signedIn<C extends ClientLike, R>(pool: PoolLike<C>, enter: (p: Principal) => void, who: Who | undefined,
                                                 options: Options, fn: (client: C, p: Principal) => Promise<R>): Promise<R> {
  const p = await signingIn(options.user, who);
  enter(p);                                        // inside a transaction of this object's, as no one else
  const client = await pool.connect();
  let broken: unknown;
  // node-postgres listens for a lost connection only on idle clients: while this one is out, an error with
  // nobody listening would stop the process. The transaction fails at its next query instead.
  const lost = (e: Error) => { broken = e; };
  client.on("error", lost);
  try {
    await client.query("BEGIN");
    const a = actAs(p);
    await client.query(a.text, a.values);
    const out = await fn(client, p);
    await client.query("COMMIT");
    return out;
  } catch (e) {
    try {
      await client.query("ROLLBACK");
    } catch (r) {
      broken = r;                                    // the connection is gone: don't give it back to the pool
    }
    throw translate(e) ?? e;
  } finally {
    client.removeListener("error", lost);
    client.release(broken as Error | undefined);
  }
}

export function authz<P extends PoolLike>(pool: P, options: Options = {}) {
  type C = ClientOf<P>;
  const clients = pool as unknown as PoolLike<C>;  // (connect() gives a C: what ClientOf<P> reads)
  const scope = transactionScope<C>();
  // inside transaction(fn), in its transaction; elsewhere, in one of its own
  const query = <T extends QueryResultRow = any>(text: string, values?: unknown[]): Promise<QueryResult<T>> =>
    scope.open()?.query<T>(text, values) ?? signedIn(clients, scope.enter, undefined, options, (c) => c.query<T>(text, values));
  return {
    pool,
    /** Runs fn in a transaction signed in as whoever the code acts for (or `who`, if given). fn acts for them too:
     *  this object's own calls made inside it (query, expect, can, ...) run in the same transaction.
     *  A transaction is one principal's: inside it, this object's work for anyone else throws before it is sent. */
    transaction: <R>(fn: (client: C) => Promise<R>, who?: Who) =>
      signedIn(clients, scope.enter, who, options, (client, p) => scope.run(client, p, () => fn(client))),
    /** One statement: inside transaction(fn), in that transaction; elsewhere, in a signed-in transaction of its own. */
    query,
    /** The runtime's functions (can, permsOf, list, share, ...): inside transaction(fn), in that transaction;
     *  elsewhere, each in a signed-in transaction of its own. */
    ...calls({ query }),
  };
}

/** The runtime's functions over a client in a signed-in transaction: calls(client).can("note", 1, "edit"). */
export { calls };

/** A function for the React kit's live updates: calls onChange whenever access may have changed (the policy's
 *  change feed, NOTIFY authz_changes). It is off until an administrator turns it on, as the owner, in a
 *  migration: INSERT INTO authz.settings VALUES ('notify_changes', 'on'), the one table of rowstile's that is
 *  written by hand (the reference's "Using it from app code"); the app role can't.
 *  One connection listens for every subscriber. Each time it begins to listen, the first time too, it tells
 *  every subscriber once: what changed while the connection was being opened was notified to nobody. If it
 *  drops, the feed listens again (after half a second, then longer). Give it a pool of its own, straight to
 *  Postgres or through a pooler in session mode: LISTEN lasts the session, and through a pooler in transaction
 *  mode it hears nothing. */
export function changes(pool: PoolLike<ListeningClient>): (onChange: () => void) => () => void {
  const subscribers = new Set<() => void>();
  let listening: ListeningClient | null = null;
  let starting = false;
  let retry: ReturnType<typeof setTimeout> | null = null;
  let wait = 500;                                  // before listening again, doubled up to 30 s
  const tell = () => subscribers.forEach((s) => s());
  const again = () => {
    if (retry || subscribers.size === 0) return;
    retry = setTimeout(() => { retry = null; start(); }, wait);
    retry.unref?.();
    wait = Math.min(wait * 2, 30_000);
  };
  const start = () => {
    if (listening || starting) return;
    starting = true;
    pool.connect().then(async (client) => {
      let gone = false;
      // the connection dropped (the database restarted, say): give the client back as broken, listen again
      const lost = (e?: Error) => {
        if (gone) return;
        gone = true;
        client.removeAllListeners("notification");
        if (listening === client) listening = null;
        client.release(e ?? new Error("the connection ended"));
        again();
      };
      client.on("error", lost);
      client.on("end", () => lost());
      client.on("notification", tell);
      try {
        await client.query("LISTEN authz_changes");
      } catch (e) {
        starting = false;
        lost(e as Error);
        return;
      }
      starting = false;
      if (gone) return;
      listening = client;
      wait = 500;
      if (subscribers.size === 0) stop();
      else tell();                                 // what changed while nobody was listening
    }, () => {
      starting = false;
      again();
    });
  };
  const stop = () => {
    const client = listening;
    if (!client) return;
    listening = null;
    for (const event of ["notification", "end", "error"] as const) client.removeAllListeners(event);
    const quiet = () => undefined;                 // until it is back in the pool, which listens itself
    client.on("error", quiet);
    const back = (e?: Error) => {
      client.removeListener("error", quiet);
      client.release(e);
    };
    client.query("UNLISTEN authz_changes").then(() => back(), (e: Error) => back(e));
  };
  return (onChange) => {
    subscribers.add(onChange);
    start();
    return () => {
      subscribers.delete(onChange);
      if (subscribers.size === 0) {
        if (retry) clearTimeout(retry);
        retry = null;
        stop();
      }
    };
  };
}

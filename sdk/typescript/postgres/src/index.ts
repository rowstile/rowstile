/**
 * rowstile with postgres.js.
 *
 *     const db = authz(postgres(url), { user: async () => (await auth())?.user.id });
 *     const notes = await db.begin((sql) => sql`SELECT * FROM app.notes`);
 *
 * Every transaction signs in with authz.act_as() as whoever the code acts for (actingAs, a job), else user(),
 * else nobody. A refused write throws Refused (with the rule and why), the not-signed-in error (AZ701) NotSignedIn.
 * Behind a pooler in transaction mode that keeps no prepared statements (PgBouncer before 1.21, or with
 * max_prepared_statements = 0; Supavisor), create the client with { prepare: false }. One that keeps them needs
 * nothing.
 */
import type { Sql, TransactionSql } from "postgres";
import {
  actAs, calls, signingIn, transactionScope, translate, type Queryable, type UserResolver, type Who,
} from "@rowstile/client";

export interface Options {
  /** Who the request is, when nothing set it with actingAs. */
  user?: UserResolver;
}

/** A postgres.js transaction as the runtime's functions take it. */
export function queryable(sql: Sql | TransactionSql): Queryable {
  return {
    query: async (text, values = []) => {
      const rows = await sql.unsafe(text, values as any[]);
      return { rows: [...rows], rowCount: rows.count };
    },
  };
}

export function authz(sql: Sql, options: Options = {}) {
  const scope = transactionScope<TransactionSql>();
  const begin = async <R>(fn: (tx: TransactionSql) => Promise<R>, who?: Who): Promise<R> => {
    const p = await signingIn(options.user, who);
    // inside a transaction of this object's: as no one else, and as p a savepoint of it
    const open = scope.enter(p);
    // fn may return an array of queries, as postgres.js's own begin takes: each runs, in the transaction
    const run = (tx: TransactionSql) => scope.run(tx, p, () => {
      const r: unknown = fn(tx);
      return (Array.isArray(r) ? Promise.all(r) : r) as Promise<R>;
    });
    try {
      if (open) return (await open.savepoint(run)) as R;
      return (await sql.begin(async (tx) => {
        const a = actAs(p);
        await tx.unsafe(a.text, a.values);
        return run(tx);
      })) as R;
    } catch (e) {
      throw translate(e) ?? e;
    }
  };
  // inside begin(fn), in its transaction; elsewhere, in one of its own
  const each: Queryable = {
    query: (text, values) => {
      const tx = scope.open();
      return tx ? queryable(tx).query(text, values) : begin((t) => queryable(t).query(text, values));
    },
  };
  return {
    sql,
    /** Runs fn in a transaction signed in as whoever the code acts for (or `who`, if given). fn acts for them too:
     *  this object's own calls made inside it (expect, can, ...) run in the same transaction, and so does a
     *  begin(fn) of theirs, as a savepoint of it. fn may return an array of queries, as postgres.js's begin takes.
     *  A transaction is one principal's: inside it, this object's work for anyone else throws before it is sent. */
    begin,
    /** The runtime's functions (can, permsOf, list, share, ...): inside begin(fn), in that transaction;
     *  elsewhere, each in a signed-in transaction of its own. */
    ...calls(each),
  };
}

export { calls };

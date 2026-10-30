/**
 * rowstile with Prisma (7 and later: driver adapters).
 *
 *     const adapter = signedIn(new PrismaPg({ connectionString }), { user: async () => (await auth())?.user.id });
 *     export const db = new PrismaClient({ adapter }).$extends(authz());
 *
 * `signedIn` wraps the driver adapter, so every transaction Prisma begins (interactive, a nested write) signs
 * in with authz.act_as() as whoever the code acts for (actingAs, a job), else user(), else nobody; a query
 * outside a transaction runs in one of its own. `authz()` turns the answers into errors: an update or delete
 * of a row the user can't see is NotFound (Prisma's P2025), of one they may not change Refused with the
 * reason, a refused create Refused naming the rule, a findUniqueOrThrow or findFirstOrThrow that finds no row
 * NotFound; and adds db.$authz (can, ids, permsOf, ...). It refuses
 * array transactions, $transaction([...]): Prisma starts them from another caller's context.
 *
 * Use the client `$extends(authz())` returns, and only that one: the client it was made from is refused
 * whenever it is used (Prisma answers the findUnique calls of one tick with one query, signed in as whoever
 * called first). That holds inside the app's own extensions too, on either side of authz(): an extension added
 * to the client authz() returns is placed before it, so authz() stays the last one, and every hook of the
 * app's runs once for each call, outside what authz() lets through.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { Prisma } from "@prisma/client/extension";
import {
  actAs, calls, idShown, idText, NotFound, signedInAlready, signingIn, translate,
  type AuthzCalls, type Id, type ObjectType, type Permission, type Principal, type Queryable, type UserResolver,
} from "@rowstile/client";

export interface Options {
  /** Who the request is, when nothing set it with actingAs. */
  user?: UserResolver;
}

// The driver adapter interfaces (@prisma/driver-adapter-utils), as much of them as this uses.
interface SqlQuery { sql: string; args: unknown[]; argTypes: unknown[] }
interface Queries {
  queryRaw(q: SqlQuery): Promise<unknown>;
  executeRaw(q: SqlQuery): Promise<number>;
}
interface Transaction extends Queries {
  readonly options?: { usePhantomQuery?: boolean };
  commit(): Promise<void>;
  rollback(): Promise<void>;
}
interface Adapter extends Queries {
  startTransaction(isolationLevel?: string): Promise<Transaction>;
  [other: string]: unknown;
}
interface AdapterFactory {
  connect(): Promise<Adapter>;
  [other: string]: unknown;
}

const ARG_TEXT = { scalarType: "string", dbType: undefined, arity: "scalar" };

// Unless the adapter says otherwise (usePhantomQuery), Prisma sends COMMIT and ROLLBACK itself, and the
// adapter's commit() and rollback() only give the connection back: so these send them too
async function end(tx: Transaction, how: "COMMIT" | "ROLLBACK"): Promise<void> {
  try {
    if (!tx.options?.usePhantomQuery) await tx.executeRaw({ sql: how, args: [], argTypes: [] });
  } finally {
    await (how === "COMMIT" ? tx.commit() : tx.rollback());
  }
}

// Set while a call comes through a client extended with authz(): the adapter refuses any other call (signedIn).
// One store for the process, even if a bundler loads this module more than once.
const KEY = Symbol.for("rowstile.prisma.extended");
const through: AsyncLocalStorage<true> = ((globalThis as Record<symbol, unknown>)[KEY] as AsyncLocalStorage<true> | undefined) ??
  ((globalThis as Record<symbol, unknown>)[KEY] = new AsyncLocalStorage<true>()) as AsyncLocalStorage<true>;
// (awaited inside: Prisma's promises only start when they are awaited)
const extended = <R>(fn: () => PromiseLike<R>): Promise<R> => through.run(true, async () => await fn());
function mustBeExtended(): void {
  if (through.getStore()) return;
  // without authz(), Prisma may answer two users' findUnique calls with one query, signed in as one of them,
  // and starts an array transaction from whichever caller came first
  throw new Error("@rowstile/prisma: this client isn't extended with authz(). Use the client $extends returns, and " +
    "only that one: export const db = new PrismaClient({ adapter }).$extends(authz())");
}

// The interactive transactions the code running now is in ($transaction(async (tx) => ...) on a client authz()
// returned): whom each adapter's signed in as, and whether it has ended (work it started may run after: then it
// signs in on its own). `mine` is the one this $transaction began. One store for the process, as above.
interface Signed { p: Principal; ended: boolean }
interface Began { signed: Map<object, Signed>; started: boolean; mine?: Signed }
const BEGAN = Symbol.for("rowstile.prisma.transaction");
const began: AsyncLocalStorage<Began> = ((globalThis as Record<symbol, unknown>)[BEGAN] as AsyncLocalStorage<Began> | undefined) ??
  ((globalThis as Record<symbol, unknown>)[BEGAN] = new AsyncLocalStorage<Began>()) as AsyncLocalStorage<Began>;

/** A driver adapter whose every transaction signs in (authz.act_as), and whose queries outside a transaction
 *  each run in a signed-in transaction of their own. Inside an interactive transaction, its work for anyone but
 *  whom the transaction signed in as throws before it is sent: a sign-in lasts the database transaction. */
export function signedIn<F extends object>(factory: F, options: Options = {}): F {
  const inner = factory as unknown as AdapterFactory;
  // who, before the transaction begins: at build time Next.js stops a render there (a signed-in page is dynamic)
  const who = async () => {
    const p = await signingIn(options.user);
    // inside a transaction of this adapter's, signed in as someone else: refused, before a connection is asked for
    const signed = began.getStore()?.signed.get(inner);
    if (signed && !signed.ended && (signed.p.type !== p.type || signed.p.id !== p.id)) throw signedInAlready(signed.p, p);
    return p;
  };
  const signIn = async (tx: Transaction, a: { text: string; values: (string | null)[] }) => {
    await tx.executeRaw({ sql: a.text, args: a.values, argTypes: a.values.map(() => ARG_TEXT) });
  };
  const wrap = (adapter: Adapter): Adapter => {
    const alone = async <R>(run: (tx: Transaction) => Promise<R>): Promise<R> => {
      mustBeExtended();
      const a = actAs(await who());
      const tx = await adapter.startTransaction();
      let out: R;
      try {
        await signIn(tx, a);
        out = await run(tx);
      } catch (e) {
        await end(tx, "ROLLBACK").catch(() => undefined);
        throw e;
      }
      await end(tx, "COMMIT");
      return out;
    };
    return new Proxy(adapter, {
      get(target, prop, receiver) {
        if (prop === "queryRaw") return (q: SqlQuery) => alone((tx) => tx.queryRaw(q));
        if (prop === "executeRaw") return (q: SqlQuery) => alone((tx) => tx.executeRaw(q));
        if (prop === "startTransaction") {
          return async (isolationLevel?: string) => {
            mustBeExtended();
            const p = await who();
            const b = began.getStore();
            if (b && !b.started) {                                    // the app's transaction, beginning
              b.started = true;
              b.mine = { p, ended: false };
              b.signed.set(inner, b.mine);
            }
            const tx = await target.startTransaction(isolationLevel);
            try {
              await signIn(tx, actAs(p));
            } catch (e) {
              await end(tx, "ROLLBACK").catch(() => undefined);
              throw e;
            }
            return tx;
          };
        }
        const v = Reflect.get(target, prop, receiver);
        return typeof v === "function" ? v.bind(target) : v;
      },
    });
  };
  return new Proxy(inner, {
    get(target, prop, receiver) {
      if (prop === "connect") return async () => wrap(await target.connect());
      const v = Reflect.get(target, prop, receiver);
      return typeof v === "function" ? v.bind(target) : v;
    },
  }) as unknown as F;
}

interface ModelInfo { dbName?: string | null; schema?: string | null }
interface RawClient {
  $queryRawUnsafe(query: string, ...values: unknown[]): Promise<any[]>;
  $transaction<R>(fn: (tx: unknown) => Promise<R>): Promise<R>;
  $extends(extension: unknown): RawClient;
  _runtimeDataModel?: { models: Record<string, ModelInfo> };
}

// Prisma's own, not in its types. A hook's query() takes the request's parameters as a second argument, which is
// how an extension has the rest of the chain run in a transaction; a transaction's client makes its promises
// with a factory that hands the transaction to their callback.
interface InternalParams { transaction?: { kind?: string } }
type Rest = (args: unknown, params?: InternalParams) => Promise<unknown>;
interface InTransaction { requestTransaction(transaction: unknown): Promise<any[]> }
async function transactionOf(tx: unknown): Promise<{ kind?: string }> {
  let found: { kind?: string } | undefined;
  const make = (tx as { _createPrismaPromise?: (cb: (t?: { kind?: string }) => Promise<void>) => PromiseLike<void> })._createPrismaPromise;
  // (the two guards are for another version of Prisma than the one the checks run: left out of the measure)
  /* v8 ignore else */
  if (typeof make === "function") await make(async (t) => { found = t; });
  /* v8 ignore next */
  if (found?.kind !== "itx") {
    throw new Error("@rowstile/prisma: this version of Prisma starts its transactions another way; " +
      "report it at https://github.com/rowstile/rowstile/issues with the version of @prisma/client");
  }
  return found;
}

/** The runtime's functions on a Prisma client, and db.$authz's type. */
export type PrismaAuthz = ReturnType<typeof calls> & {
  /** The ids the signed-in user holds perm on (Prisma has no subqueries): where: { id: { in: await
   *  db.$authz.ids("folder", "edit", Number) } }. For a long list, prefer a view or a raw query. */
  ids<T extends ObjectType, K = string>(type: T, perm: Permission<T>, as?: (id: string) => K): Promise<K[]>;
};

export interface ExtensionOptions {
  /** A model's key fields, in the policy's key order, where it isn't `id`, the where's one unique field, or a
   *  compound key Prisma names for its fields (project_id_user_id). */
  keys?: Record<string, string[]>;
}

/** The client extension: refusals and hidden rows as errors, and db.$authz. */
export function authz(options: ExtensionOptions = {}) {
  return Prisma.defineExtension((client) => {
    const raw = client as unknown as RawClient;
    // (Prisma 7 always has the data model: without it, another version, left out of the measure)
    /* v8 ignore next */
    const models = raw._runtimeDataModel?.models ?? {};
    // the schema of a table the database's words name without one: a model's table is its @@map, else its name
    const schemaOf = (table: string) => {
      for (const [name, m] of Object.entries(models)) if ((m.dbName ?? name) === table && m.schema) return m.schema;
      return undefined;
    };
    const tableOf = (model: string) => {
      const m = models[model];
      const name = m?.dbName ?? model;
      return m?.schema ? `${m.schema}.${name}` : name;
    };
    // the row's key (the policy's key for the table) from the where of an update, a delete or a findUnique: the
    // fields options.keys names for the model, else id, else its one unique field or compound key (Prisma refuses
    // any of them without a where before a query)
    const keyOf = (model: string, where: Record<string, unknown>): Id | undefined => {
      const named = options.keys?.[model];
      if (named) {
        const vals = named.map((k) => where[k]);
        if (vals.every(isScalar)) return (vals.length === 1 ? vals[0] : vals) as Id;
        for (const v of Object.values(where)) {
          const o = v as Record<string, unknown> | null;
          if (o && typeof o === "object" && named.every((k) => isScalar(o[k]))) return named.map((k) => o[k]) as Id;
        }
        return undefined;
      }
      if (isScalar(where.id)) return where.id as Id;
      const entries = Object.entries(where);
      if (entries.length !== 1) return undefined;
      const [name, v] = entries[0];
      if (isScalar(v)) return v as Id;
      // a compound key's fields, in a plain object: not a date (or bytes, a decimal), which isn't written as the
      // database writes it. In the key's own order, which its name gives (Prisma names it for its fields, joined
      // with "_": project_id_user_id), not in the order the app wrote them; a key given a name of its own
      // (@@id(name: ...)) doesn't say, and options.keys must
      if (v && typeof v === "object" && Object.getPrototypeOf(v) === Object.prototype && Object.values(v).every(isScalar)) {
        const o = v as Record<string, unknown>;
        const fields = Object.keys(o).sort((a, b) => name.indexOf(a) - name.indexOf(b));
        if (fields.join("_") === name) return fields.map((f) => o[f]) as Id;
      }
      return undefined;
    };
    // through the client this returns (set below), whose last hook lets the query through
    let self: RawClient = raw;
    const q: Queryable = {
      query: async (text, values = []) => ({ rows: await self.$queryRawUnsafe(text, ...values) }),
    };
    const c = calls(q);
    // The runtime's functions asked inside the app's interactive transaction, for a call made in one: an update or a
    // read that found no row leaves it usable, and a question outside it would wait for a connection of its own,
    // which on a pool of one the transaction holds until Prisma's timeout. A Prisma promise runs in the transaction
    // it is handed (requestTransaction: how Prisma runs an array's queries in theirs).
    const askingIn = (transaction: InternalParams["transaction"]) => transaction?.kind !== "itx" ? c : calls({
      query: async (text, values = []) => ({
        rows: await (self.$queryRawUnsafe(text, ...values) as unknown as InTransaction).requestTransaction(transaction),
      }),
    });
    const $authz: PrismaAuthz = {
      ...c,
      ids: async (type, perm, as) => {
        const out = await c.list(type, perm);
        return (as ? out.map(as) : out) as any[];
      },
    };
    const hooks = client.$extends({
      name: "rowstile",
      query: {
        async $allOperations({ model, operation, args, query, ...rest }) {
          const internal = (rest as { __internalParams?: InternalParams }).__internalParams;
          if (internal?.transaction?.kind === "batch") {
            // Prisma starts an array's transaction later, from whichever request came first in that tick: it
            // might sign in as someone else
            throw new Error("@rowstile/prisma: $transaction([...]) can't be signed in as the right user; use " +
              "$transaction(async (tx) => { ... }) instead");
          }
          try {
            if (!internal?.transaction && model && (operation === "findUnique" || operation === "findUniqueOrThrow")) {
              // Prisma answers the findUnique calls of one tick together, from the first caller's context: run each
              // in an interactive transaction of its own, which begins (and signs in) in this caller's context.
              // What is left of the call (this hook is the last: Prisma's own work) runs in it; calling the model
              // again on the transaction would run every hook of the app's a second time
              return await extended(() => raw.$transaction(async (tx) =>
                (query as Rest)(args, { ...internal, transaction: await transactionOf(tx) })));
            }
            return await extended(() => query(args));
          } catch (e) {
            if (model && isP2025(e) && (operation === "update" || operation === "delete")) {
              const table = tableOf(model);
              const key = keyOf(model, (args as { where: Record<string, unknown> }).where);
              if (key !== undefined) {
                const v = await askingIn(internal?.transaction).verdict(table, operation, key).catch(() => undefined);
                if (v !== undefined) {
                  (v as { cause?: unknown }).cause = e;
                  throw v;
                }
              }
            }
            // a read that must find a row and found none: the row isn't there, or this user can't see it (the
            // two answer alike). Left as Prisma's P2025 it is a 500, where an update or a delete is a 404.
            // findUnique's where is a key; findFirst's is any filter, which names a row only by its id
            if (model && isP2025(e) && (operation === "findUniqueOrThrow" || operation === "findFirstOrThrow")) {
              const where = (args as { where?: Record<string, unknown> }).where;
              const key = operation === "findUniqueOrThrow" ? keyOf(model, where!)
                : isScalar(where?.id) ? where?.id as Id : undefined;
              const table = await askingIn(internal?.transaction).tableName(tableOf(model)).catch(() => tableOf(model));
              throw new NotFound(table, key === undefined ? undefined : idShown(key), { cause: e });
            }
            throw translate(e, schemaOf) ?? e;
          }
        },
      },
      client: { $authz },
    });
    // a second layer, so that $parent has the hooks above: transactions begin through this client too. It
    // changes nothing in $transaction's type, nor in $extends's.
    // The transaction begins inside the mark, but the app's callback runs outside it: the callback is the app's
    // code, and a client not extended with authz() is refused there as anywhere (its findUnique calls would be
    // answered together). Queries through tx go through the transaction, which needs no mark. What the callback
    // returns is awaited outside the mark too: a Prisma query it returns unawaited starts only then.
    const transactions = {
      $transaction(this: unknown, ...args: unknown[]) {
        const parent = (Prisma.getExtensionContext(this) as unknown as { $parent: { $transaction(...a: unknown[]): Promise<unknown> } }).$parent;
        const [fn, ...rest] = args;
        const app = typeof fn === "function"
          ? (tx: unknown) => through.exit(async () => await (fn as (tx: unknown) => unknown)(tx)) : fn;
        // (awaited inside: the transaction begins, and signs in, in the store's scope)
        const b: Began = { signed: new Map(began.getStore()?.signed), started: false };   // (and those it is inside)
        return extended(() => began.run(b, async () => {
          try {
            return await parent.$transaction(app, ...rest);
          } finally {
            if (b.mine) b.mine.ended = true;
          }
        }));
      },
      // An extension added to this client goes before authz(), which is then applied again: Prisma calls query
      // hooks in the order they were added, so a hook added after authz()'s would run inside what it lets
      // through, and the client authz() was made from would not be refused there. (A function is called with
      // this client, as Prisma does: what it adds comes back here.)
      $extends(this: unknown, extension: unknown) {
        if (typeof extension === "function") return (extension as (client: unknown) => unknown)(this);
        return raw.$extends(extension).$extends(authz(options));
      },
    };
    const out = hooks.$extends({ name: "rowstile-transactions", client: transactions as {} });
    self = out as unknown as RawClient;
    return out;
  });
}

function isScalar(v: unknown): boolean {
  return typeof v === "string" || typeof v === "number" || typeof v === "bigint";
}

function isP2025(e: unknown): boolean {
  return Boolean(e && typeof e === "object" && (e as { code?: unknown }).code === "P2025");
}

export { idText, type AuthzCalls };

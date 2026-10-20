/**
 * rowstile for TypeScript apps.
 *
 * Every transaction signs in as whoever the request (or the job) acts for, with `authz.act_as()`; the
 * database's refusals become `Refused` (a 403 with the reason), rows the user can't see become `NotFound`
 * (a 404). This package holds no rowstile logic: it calls the `authz.*` functions the policy made, and
 * translates their answers. The drivers' packages (`@rowstile/pg`, `/postgres`, `/prisma`, `/drizzle`) use it.
 *
 *     import { actingAs } from "@rowstile/client";
 *     await actingAs(42, async () => { ... });        // every transaction in here signs in as user 42
 *
 * The names the policy declares come from the generated file (`rowstile client`, e.g. `src/authz.gen.ts`),
 * which registers them here, so a misspelled type or permission doesn't type-check.
 */
import { AsyncLocalStorage } from "node:async_hooks";

// --- the policy's names ----------------------------------------------------------------------------------
/** Filled in by the generated file: `declare module "@rowstile/client" { interface Register { ... } }`. */
// eslint-disable-next-line @typescript-eslint/no-empty-interface
export interface Register {}
type Registered = Register extends { permissions: infer P } ? P : { readonly [type: string]: readonly string[] };
type RegisteredShared = Register extends { sharedRelations: infer S } ? S
  : { readonly [type: string]: { readonly [relation: string]: readonly string[] } };
/** A type the policy declares ("folder"). */
export type ObjectType = Extract<keyof Registered, string>;
/** A permission type T has ("edit"). */
export type Permission<T extends ObjectType = ObjectType> =
  Registered[T] extends readonly (infer P)[] ? Extract<P, string> : string;
/** A type with relations people may share. */
export type SharedType = Extract<keyof RegisteredShared, string>;
/** A relation of T people may share ("editor"). */
export type SharedRelation<T extends SharedType = SharedType> = Extract<keyof RegisteredShared[T], string>;

/** An object's id; for a composite key, its columns in order: [orgId, id]. */
export type Id = string | number | bigint | readonly (string | number | bigint)[];

/** An id as the database compares it: a composite key as Postgres writes a row (every field quoted); a key of
 *  one column given as an array is that value. */
export function idText(id: Id): string {
  if (Array.isArray(id)) {
    if (id.length === 1) return String(id[0]);
    return "(" + id.map((v) => '"' + String(v).replace(/["\\]/g, (c) => "\\" + c) + '"').join(",") + ")";
  }
  return String(id);
}

/** A row's key as the database writes it, for a message: 7, or (1,2) for a composite key (a field is quoted
 *  only where Postgres would: when it is empty or holds a comma, a quote, a parenthesis or a space). */
export function idShown(id: Id): string {
  if (!Array.isArray(id)) return String(id);
  if (id.length === 1) return String(id[0]);
  return "(" + id.map((v) => {
    if (v === null || v === undefined) return "";
    const text = String(v);
    return text === "" || /[",\\()\s]/.test(text) ? '"' + text.replace(/\\/g, "\\\\").replace(/"/g, '""') + '"' : text;
  }).join(",") + ")";
}

// --- who a transaction acts for ----------------------------------------------------------------------------
/** A user (type "user"), another principal type the policy declares (a service, a bot), or nobody (id null:
 *  only what `anyone` may see). */
export interface Principal {
  readonly type: string;
  readonly id: string | null;
}
/** 42, "42", ["service", 3], a Principal, or null / undefined (nobody). A plain id is a user's, whatever it holds:
 *  "service:3" is the user whose id that is (ids often come from outside: a username, an identity provider's
 *  subject), never service 3. Another principal type is named: ["service", 3]. */
export type Who = Principal | string | number | bigint | readonly [string, string | number | bigint | null] | null | undefined;

export const NOBODY: Principal = Object.freeze({ type: "user", id: null });

export function principal(who: Who): Principal {
  if (who === null || who === undefined) return NOBODY;
  if (Array.isArray(who)) {
    const [type, id] = who as readonly [string, string | number | bigint | null];
    return Object.freeze({ type: String(type), id: id === null || id === undefined ? null : String(id) });
  }
  if (typeof who === "object") {
    const p = who as Principal;
    return Object.freeze({ type: p.type ?? "user", id: p.id === null || p.id === undefined ? null : String(p.id) });
  }
  return Object.freeze({ type: "user", id: String(who) });
}

/** What describe() wrote, read back: "service:3" is service 3, "42" user 42, "nobody" nobody. For text your own
 *  code wrote (a job's argument, the audit trail's `by`), not for an id that came from outside. */
export function parsePrincipal(text: string): Principal {
  if (text === "nobody") return NOBODY;
  const colon = text.indexOf(":");
  if (colon > 0 && !text.startsWith("(")) return Object.freeze({ type: text.slice(0, colon), id: text.slice(colon + 1) });
  return Object.freeze({ type: "user", id: text });
}

/** "42", "service:3" or "nobody". */
export function describe(p: Principal): string {
  return p.id === null ? "nobody" : p.type === "user" ? p.id : `${p.type}:${p.id}`;
}

// One store for the process, even if bundlers load this module more than once (Next.js bundles per route).
interface Shared {
  store: AsyncLocalStorage<Principal>;
  hooks: ((p: Principal) => unknown)[];
}
const KEY = Symbol.for("rowstile.context");
const shared: Shared = ((globalThis as Record<symbol, unknown>)[KEY] as Shared | undefined) ??
  ((globalThis as Record<symbol, unknown>)[KEY] = { store: new AsyncLocalStorage<Principal>(), hooks: [] }) as Shared;

/** Who the code running now acts for (set by actingAs, a job, or a web integration), or undefined if unset. */
export function current(): Principal | undefined {
  return shared.store.getStore();
}

/** Runs fn in p's scope; a promise it returns is awaited in the scope too, as Prisma's queries only start when
 *  they are awaited. */
function inScope<R>(p: Principal, fn: () => R): R {
  return shared.store.run(p, () => {
    const r = fn();
    if (r && typeof (r as { then?: unknown }).then === "function") return (async () => await r)() as R;
    return r;
  });
}

/** Runs fn acting for `who`: every transaction it begins (the drivers' packages) signs in as them. */
export function actingAs<R>(who: Who, fn: () => R): R {
  return inScope(principal(who), fn);
}

/** A background job (BullMQ, Next.js `after()`, a cron handler) that acts for `who`, whatever started it:
 *  job(["service", 3], async (payload) => { ... }). */
export function job<A extends unknown[], R>(who: Who, fn: (...args: A) => R): (...args: A) => R {
  const p = principal(who);
  return (...args: A) => inScope(p, () => fn(...args));
}

/** Who the request is, when nothing set it with actingAs: e.g. async () => (await auth())?.user.id */
export type UserResolver = () => Who | Promise<Who>;

/** Something to run before a transaction signs in (the Next.js integration keeps signed-in reads out of caches). */
export function beforeSignIn(hook: (p: Principal) => unknown): void {
  if (!shared.hooks.includes(hook)) shared.hooks.push(hook);
}

/** Whom the next transaction signs in as: `who` if the call was given one (null: nobody), else whoever the
 *  code acts for, else user(), else nobody. The hooks run for each: a transaction told who it acts for is
 *  kept out of caches like any other. */
export async function signingIn(user?: UserResolver, who?: Who): Promise<Principal> {
  let p = who !== undefined ? principal(who) : current();
  if (p === undefined) p = user ? principal(await user()) : NOBODY;
  for (const hook of shared.hooks) await hook(p);
  return p;
}

/** The statement that signs a transaction in, with its parameters. */
export function actAs(p: Principal): { text: string; values: (string | null)[] } {
  return { text: "SELECT authz.act_as($1, $2)", values: p.id === null ? [null, null] : [p.type, p.id] };
}

/** A SQL string literal that means the same whatever standard_conforming_strings says (a role, a database or a
 *  session may turn it off): quotes doubled, and a value holding a backslash written E'...' with its backslashes
 *  doubled, so that no backslash can end the string early. */
export function literal(value: string | null): string {
  if (value === null) return "NULL";
  const text = value.replace(/'/g, "''");
  return text.includes("\\") ? "E'" + text.replace(/\\/g, "\\\\") + "'" : "'" + text + "'";
}

/** The same statement with its values written in, for APIs that take no parameters. */
export function actAsSql(p: Principal): string {
  return p.id === null ? "SELECT authz.act_as(NULL, NULL)" : `SELECT authz.act_as(${literal(p.type)}, ${literal(p.id)})`;
}

// --- errors ---------------------------------------------------------------------------------------------
/** An RFC 9457 problem body: problemOf(e)'s fields, and what route() answers with. */
export interface Problem {
  /** https://rowstile.dev/problems/refused, /not-found, /not-signed-in, /bad-argument or /conflict */
  type: string;
  title: string;
  status: number;
  /** the database's words: for a refusal, who may not do what, where */
  detail: string;
  /** a refusal's table (schema.table) and command (insert, update, delete, select), when the error names them */
  table?: string | null;
  command?: string | null;
  /** a refusal's reason, a line each: the rule, then what holds and what is missing */
  why?: string[];
  /** rowstile's code: AZ709 for a rule's refusal (rowstile help AZ709) */
  code?: string;
}

/** The database refused a write, and said why: the rule (table and command), and the explanation. */
export class Refused extends Error {
  readonly status = 403;
  /** rowstile's code for it: AZ709 for a rule's refusal, the database's own for another (AZ705: a share). */
  readonly code: string;                           // rowstile help AZ709
  constructor(message: string, public table?: string, public command?: string, public why: string[] = [],
              options?: { cause?: unknown; code?: string }) {
    super(message, options);
    this.name = "Refused";
    this.code = options?.code ?? "AZ709";
  }
  problem(): Problem {
    return { type: "https://rowstile.dev/problems/refused", title: "Forbidden", status: 403, detail: this.message,
             table: this.table ?? null, command: this.command ?? null, why: this.why, code: this.code };
  }
}

/** The row isn't there, or whoever the transaction acts for can't see it. */
export class NotFound extends Error {
  readonly status = 404;
  constructor(public table?: string, public id?: string, options?: { cause?: unknown }) {
    super(`${table ?? "the row"}${id === undefined ? "" : " " + id} not found`, options);
    this.name = "NotFound";
  }
  problem(): Problem {
    return { type: "https://rowstile.dev/problems/not-found", title: "Not Found", status: 404, detail: this.message };
  }
}

/** A query that needs to know who is asking ran in a transaction nobody signed in to (strict sign-in). */
export class NotSignedIn extends Error {
  readonly code = "AZ701";                         // rowstile help AZ701
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "NotSignedIn";
  }
}

/** authz.connection_check() found that the app's connection skips row-level security (or worse). */
export class ConnectionProblem extends Error {
  constructor(public problems: string[]) {
    super("the app's database connection can't be used with rowstile: " + problems.join("; "));
    this.name = "ConnectionProblem";
  }
}

/** The error and the driver's errors inside it: pg's and postgres.js's are the error itself, Drizzle keeps
 *  the driver's as the cause, Prisma's driver adapters in meta.driverAdapterError.cause. */
function chain(e: unknown): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  const todo: unknown[] = [e];
  while (todo.length) {
    const x = todo.shift();
    if (!x || typeof x !== "object" || out.includes(x as Record<string, unknown>)) continue;
    const o = x as Record<string, unknown>;
    out.push(o);
    todo.push(o.cause, o.meta, o.driverAdapterError, o.originalError);
  }
  return out;
}

interface DbError {
  code: string;
  message: string;
  detail?: string;
  hint?: string;
  schema?: string;
  table?: string;
  constraint?: string;
}

const str = (v: unknown): string | undefined => (typeof v === "string" && v ? v : undefined);

/** The Postgres error in e, if there is one: its SQLSTATE and fields, whichever driver raised it. */
export function dbError(e: unknown): DbError | null {
  for (const o of chain(e)) {
    if (o.clientVersion !== undefined) continue;               // Prisma's own error: its code is Prisma's
    const code = str(o.originalCode) ?? str(o.sqlState) ?? str(o.code);
    // five characters, and not Node's own (EPIPE, EPERM: no SQLSTATE class begins with E)
    if (!code || !/^[0-9A-Z]{5}$/.test(code) || code.startsWith("E")) continue;
    return {
      code,
      message: str(o.originalMessage) ?? str(o.message) ?? "",
      detail: str(o.detail), hint: str(o.hint),
      schema: str(o.schema) ?? str(o.schema_name), table: str(o.table) ?? str(o.table_name),
      constraint: str(o.constraint) ?? str(o.constraint_name),
    };
  }
  return null;
}

/** rowstile's code for a database error (AZ709; `rowstile help AZ709` says what it means): from its HINT, where
 *  the runtime puts it, or its message. Undefined for an error rowstile didn't raise. */
export function errorCode(e: unknown): string | undefined {
  const err = dbError(e);
  for (const text of [err?.hint, err?.message]) {
    const m = /(?:rowstile|rowfence) help (AZ\d{3})|\[(AZ\d{3})\]/.exec(text ?? "");
    if (m) return m[1] ?? m[2];
  }
  return undefined;
}

export function sqlstate(e: unknown): string | undefined {
  return dbError(e)?.code;
}

const RLS_GENERIC = /^new row violates row-level security policy (\(USING expression\) )?for table "([^"]+)"/;
const OURS = /may not (insert|update|delete) this row (?:into|of) (\S+?)(?: to these values)?$/;
/** The table in a column rule's refusal, "changing locked of app.notes 7 needs: folder.manage" (always an
 *  update); undefined for any other message. Read with indexOf: a pattern here would backtrack on a long one. */
function columnRuleTable(message: string): string | undefined {
  const of = message.indexOf(" of "), needs = message.indexOf(" needs: ");
  if (!message.startsWith("changing ") || of < 0 || needs < of) return undefined;
  const named = message.slice(of + 4, needs);                   // "app.notes 7"
  return named.split(" ", 1)[0] || undefined;
}

/** A Refused for an error that is the database refusing a write (SQLSTATE 42501, raised by rowstile's
 *  policies with the rule and why), else null. `schemaOf` qualifies a bare table name (Prisma knows it).
 *  Another 42501 (a table the app role was never granted) is the app's mistake, not a refusal: null. */
export function refusal(e: unknown, schemaOf?: (table: string) => string | undefined): Refused | null {
  const err = dbError(e);
  if (!err || err.code !== "42501") return null;
  const generic = RLS_GENERIC.exec(err.message);
  if (generic) {
    const schema = err.schema ?? schemaOf?.(generic[2]);
    const table = schema ? `${schema}.${generic[2]}` : generic[2];
    if (generic[1]) {
      // an upsert (INSERT ... ON CONFLICT DO UPDATE) whose existing row this user may not update, or not see
      return new Refused(`${err.message}: the row is there already, and the update rule (or the select rule) doesn't ` +
        "let this user change it (ON CONFLICT DO UPDATE)", table, "update", [], { cause: e });
    }
    // Postgres's own words, not rowstile's: the row was allowed in, but may not be read back (INSERT ...
    // RETURNING, or an ORM that reads the new row, as Prisma's create does), which the select rule decides
    return new Refused(`${err.message}: the write was allowed, but the select rule doesn't let this user read the row ` +
      "back (RETURNING); read it back only if the select rule allows it", table, "select", [], { cause: e });
  }
  const ours = OURS.exec(err.message);
  const code = errorCode(e);
  if (!ours && !err.constraint?.startsWith("authz_") && code === undefined) return null;
  // sign in first (AZ714) is a 42501 too, but no refusal: a 401
  if (code !== undefined && CALL_PROBLEMS.has(code)) return null;
  // the error's own fields say which table and command; a driver that drops them (Prisma's adapters) leaves
  // the message, which names both
  const column = columnRuleTable(err.message);
  const table = err.schema && err.table ? `${err.schema}.${err.table}` : err.table ?? ours?.[2] ?? column;
  const command = err.constraint?.startsWith("authz_") ? err.constraint.slice(6) : ours?.[1] ?? (column ? "update" : undefined);
  return new Refused(err.message, table, command, err.detail ? err.detail.split("\n") : [], { cause: e, code });
}

/** Whether e is strict sign-in's error (rowstile help AZ701): a query that needs to know who is asking, and nobody
 *  signed in. A login refused (AZ703) and settings changed by hand (AZ702) share its SQLSTATE, 28000, but are no
 *  such thing. */
export function notSignedIn(e: unknown): boolean {
  const code = errorCode(e);
  return sqlstate(e) === "28000" && (code === undefined || code === "AZ701");
}

/** e as rowstile's error: Refused, NotFound or NotSignedIn as they are, a database refusal as Refused, strict
 *  sign-in's error as NotSignedIn; null for anything else. */
export function translate(e: unknown, schemaOf?: (table: string) => string | undefined): Refused | NotFound | NotSignedIn | null {
  if (e instanceof Refused || e instanceof NotFound || e instanceof NotSignedIn) return e;
  const r = refusal(e, schemaOf);
  if (r) return r;
  if (notSignedIn(e)) {
    return new NotSignedIn("nobody signed in in this transaction: every transaction must begin with authz.act_as() " +
      "(the drivers' packages do it; is this query outside them?)", { cause: e });
  }
  return null;
}

// rowstile's codes for a call the database turned down that is no refusal, and what their pages say to answer
// (rowstile help AZ703: a login refused; AZ708: what the call names isn't there; AZ710: a missing or wrong
// argument; AZ713: moved inside itself; AZ714: sign in first)
const CALL_PROBLEMS = new Map<string, Pick<Problem, "type" | "title" | "status">>([
  ["AZ703", { type: "https://rowstile.dev/problems/not-signed-in", title: "Unauthorized", status: 401 }],
  ["AZ708", { type: "https://rowstile.dev/problems/not-found", title: "Not Found", status: 404 }],
  ["AZ710", { type: "https://rowstile.dev/problems/bad-argument", title: "Bad Request", status: 400 }],
  ["AZ713", { type: "https://rowstile.dev/problems/conflict", title: "Conflict", status: 409 }],
  ["AZ714", { type: "https://rowstile.dev/problems/not-signed-in", title: "Unauthorized", status: 401 }],
]);

/** The problem body and status for e (Refused: 403, NotFound: 404), or null. A call the database turns down that is
 *  no refusal answers as its code's page says, with the database's words: a login refused or a call that needs
 *  someone signed in 401 (AZ703, AZ714), something it names that isn't there 404 (AZ708: a share with someone who
 *  doesn't exist), an argument missing or wrong 400 (AZ710: a negative page size), a move inside itself 409
 *  (AZ713). */
export function problemOf(e: unknown): Problem | null {
  const t = translate(e);
  if (t instanceof Refused || t instanceof NotFound) return t.problem();
  const code = errorCode(e);
  const call = code === undefined ? undefined : CALL_PROBLEMS.get(code);
  return call ? { ...call, detail: dbError(e)!.message, code } : null;
}

/** A Response (application/problem+json) for e, or null: for route handlers. */
export function problemResponse(e: unknown): Response | null {
  const p = problemOf(e);
  return p ? new Response(JSON.stringify(p), { status: p.status, headers: { "content-type": "application/problem+json" } }) : null;
}

/** The errors among authz.connection_check()'s rows. */
export function checkProblems(rows: { severity: string; problem: string }[]): string[] {
  return rows.filter((r) => r.severity === "error").map((r) => r.problem);
}

// --- the runtime's functions, over any driver ---------------------------------------------------------------
/** Anything that runs one statement with $1, $2 parameters and returns its rows. */
export interface Queryable {
  query(text: string, values?: unknown[]): Promise<{ rows: any[]; rowCount?: number | null }>;
}

/** A share, as authz.list_shares returns it. */
export interface Share {
  relation: string;
  subject_type: string;
  subject_id: string;
  subject_relation: string;
  [column: string]: unknown;
}

/** What the React kit's routes need; each driver's package gives it (Prisma: db.$authz). */
export interface AuthzCalls {
  can<T extends ObjectType>(type: T, id: Id, perm: Permission<T>): Promise<boolean>;
  perms<T extends ObjectType>(type: T, id: Id): Promise<Permission<T>[]>;
  permsOf<T extends ObjectType>(type: T, ids: readonly Id[]): Promise<Record<string, Permission<T>[]>>;
  list<T extends ObjectType>(type: T, perm: Permission<T>, page?: { after?: Id; limit?: number }): Promise<string[]>;
  listShares<T extends ObjectType>(type: T, id: Id): Promise<Share[]>;
  share<T extends SharedType>(type: T, id: Id, relation: SharedRelation<T>, subjectType: string, subjectId: Id,
                              subjectRelation?: string): Promise<void>;
  unshare<T extends SharedType>(type: T, id: Id, relation: SharedRelation<T>, subjectType: string, subjectId: Id,
                                subjectRelation?: string): Promise<void>;
  requestAccess<T extends SharedType>(type: T, id: Id, relation: SharedRelation<T>, reason: string): Promise<string>;
  explainRule(table: string, command: "insert" | "update" | "delete", id?: Id, row?: object): Promise<string[] | null>;
  connectionCheck(): Promise<{ severity: string; problem: string }[]>;
}

// The policy names tables with their schema; a table named without one (a model that names no schema) is
// looked up on the search_path
const TABLE_NAME = "coalesce((SELECT n.nspname || '.' || c.relname FROM pg_catalog.pg_class c " +
  "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE position('.' in $1::text) = 0 " +
  "AND c.oid = pg_catalog.to_regclass(pg_catalog.quote_ident($1::text))), $1::text)";
const EXPLAIN_RULE = "SELECT authz.explain_rule(t.tbl, $2, $3, $4::jsonb) AS e, t.tbl, " +
  // who is signed in, in the words the database's own refusals use
  "coalesce((SELECT p.principal_type || ' ' || p.principal_id FROM authz.principal() p), 'someone not signed in') AS who " +
  `FROM (SELECT ${TABLE_NAME} AS tbl) t`;

/** The runtime's functions over q (a signed-in transaction, or something that signs each query in). */
export function calls(q: Queryable): AuthzCalls & {
  expect<R>(result: R, table: string, command: "update" | "delete", id: Id, row?: object): Promise<R>;
  /** What an UPDATE or DELETE that changed nothing was, asked of the database: the error to throw. */
  verdict(table: string, command: string, id: Id, row?: object): Promise<NotFound | Refused>;
  /** The table as the policy names it, with its schema: a bare name (a model that names no schema) is looked
   *  up on the search_path, once. */
  tableName(table: string): Promise<string>;
  check(): Promise<void>;
} {
  const one = async (text: string, values: unknown[]) => (await q.query(text, values)).rows[0];
  const names = new Map<string, string>();        // a table as the app names it -> as the policy does
  const c = {
    can: async (type: string, id: Id, perm: string) =>
      Boolean((await one("SELECT authz.can($1, $2::text, $3) AS ok", [type, idText(id), perm])).ok),
    // (an array, empty at worst: authz.perms never answers null)
    perms: async (type: string, id: Id) =>
      (await one("SELECT authz.perms($1, $2::text) AS p", [type, idText(id)])).p as any[],
    permsOf: async (type: string, ids: readonly Id[]) => {
      const rows = (await q.query("SELECT id, perms FROM authz.perms_of($1, $2::text[])", [type, ids.map(idText)])).rows;
      return Object.fromEntries(rows.map((r) => [r.id, r.perms])) as Record<string, any[]>;
    },
    list: async (type: string, perm: string, page: { after?: Id; limit?: number } = {}) =>
      (await q.query("SELECT x FROM authz.list($1, $2, $3, $4) x",
        [type, perm, page.after === undefined ? null : idText(page.after), page.limit ?? null])).rows.map((r) => r.x as string),
    listShares: async (type: string, id: Id) =>
      (await q.query("SELECT * FROM authz.list_shares($1, $2::text)", [type, idText(id)])).rows as Share[],
    share: async (type: string, id: Id, relation: string, subjectType: string, subjectId: Id, subjectRelation = "") => {
      // void functions in FROM: some drivers (Prisma) can't read a void column
      await q.query("SELECT 1 AS ok FROM authz.share($1, $2::text, $3, $4, $5::text, $6)",
        [type, idText(id), relation, subjectType, idText(subjectId), subjectRelation]);
    },
    unshare: async (type: string, id: Id, relation: string, subjectType: string, subjectId: Id, subjectRelation = "") => {
      await q.query("SELECT 1 AS ok FROM authz.unshare($1, $2::text, $3, $4, $5::text, $6)",
        [type, idText(id), relation, subjectType, idText(subjectId), subjectRelation]);
    },
    requestAccess: async (type: string, id: Id, relation: string, reason: string) =>
      String((await one("SELECT authz.request_access($1, $2::text, $3, $4) AS id", [type, idText(id), relation, reason])).id),
    explainRule: async (table: string, command: string, id?: Id, row?: object) =>
      ((await one(EXPLAIN_RULE,
        [table, command, id === undefined ? null : idText(id), row === undefined ? null : JSON.stringify(row)])).e ?? null) as string[] | null,
    connectionCheck: async () =>
      (await q.query("SELECT severity, problem FROM authz.connection_check()", [])).rows as { severity: string; problem: string }[],
    /** The result of an UPDATE or DELETE (rows, a count, or a driver's result): returned if it changed a row,
     *  otherwise NotFound (the user can't see the row) or Refused (they may not, and why). */
    expect: async <R>(result: R, table: string, command: "update" | "delete", id: Id, row?: object): Promise<R> => {
      if (changed(result)) return result;
      throw await c.verdict(table, command, id, row);
    },
    verdict: async (table: string, command: string, id: Id, row?: object) => {
      const got = await one(EXPLAIN_RULE, [table, command, idText(id), row === undefined ? null : JSON.stringify(row)]);
      // named as the database names it, as in a refused insert: "public.Note" for a model that says "Note" (the
      // statement's tbl and who are text, never null)
      const named = String(got.tbl);
      names.set(table, named);
      return verdict(named, command, id, (got.e ?? null) as string[] | null, String(got.who));
    },
    tableName: async (table: string) => {
      if (!names.has(table) && !table.includes(".")) {
        names.set(table, String((await one(`SELECT ${TABLE_NAME} AS tbl`, [table])).tbl));
      }
      return names.get(table) ?? table;
    },
    /** Throws ConnectionProblem if this connection skips row-level security. As nobody: it runs at start-up,
     *  where there is no request to ask who is signed in. */
    check: () => actingAs(null, async () => {
      const problems = checkProblems(await c.connectionCheck());
      if (problems.length) throw new ConnectionProblem(problems);
    }),
  };
  return c as any;
}

/** Whether an UPDATE or DELETE's result changed anything: rows, a count, {count}, {rowCount}, postgres.js's .count. */
export function changed(result: unknown): boolean {
  if (typeof result === "number" || typeof result === "bigint") return Number(result) > 0;
  if (result && typeof result === "object") {
    const o = result as Record<string, unknown>;
    for (const k of ["rowCount", "count", "rowsAffected", "affectedRows"]) {
      if (typeof o[k] === "number") return (o[k] as number) > 0;
    }
    if (Array.isArray(result)) return result.length > 0;
    if (Array.isArray(o.rows)) return o.rows.length > 0;
  }
  return Boolean(result);
}

/** What an UPDATE or DELETE that changed nothing was: NotFound when the row isn't there for this user (why is
 *  null), or when the rule allows the write (its first line says yes: the statement matched nothing for
 *  another reason, such as a where with more than the key); Refused with the reason otherwise, worded as the
 *  database words a refused insert: "permission denied: user 2 may not update row 7 of app.notes".
 *  who: "user 2", as the database says it; left out, whoever the code acts for now. */
export function verdict(table: string, command: string, id: Id, why: string[] | null, who?: string): NotFound | Refused {
  if (why === null || /^\s*yes\b/.test(why[0])) return new NotFound(table, idShown(id));
  const p = current() ?? NOBODY;
  const by = who ?? (p.id === null ? "someone not signed in" : `${p.type} ${p.id}`);
  return new Refused(`permission denied: ${by} may not ${command} row ${idShown(id)} of ${table}`, table, command, why);
}

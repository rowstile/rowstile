/**
 * Electric behind the app's own server (a preview): a route that answers a client's shape request with Electric's
 * answer, the shape's table, filter and columns set here, whatever the client sent.
 *
 *     import { shapes } from "./shapes.gen.js";                       // rowstile client electric
 *     const files = electricShape(shapes["app.files"], {
 *       url: process.env.ELECTRIC_URL!,                               // http://electric:3000/v1/shape
 *       signedIn: (req) => actingAs(userOf(req), () => sql.transaction((c) => syncPrincipal(c))),
 *       vary: ["cookie"],
 *     });
 *     export { files as GET, files as POST };                        // a route handler: fetch's Request, Response
 *
 * Every request asks the database who it is, in the app's own way (a session, a key, a token): nobody is 401, a
 * session limited by scopes or viewing as someone 403 (the sync index holds what each principal may read, without
 * scopes). The filter is the sync index's join for that principal; the key columns are always synced, a column the
 * policy masks never. A client may narrow what it gets with Electric's subsets (`subset__where`, or a POST's body),
 * which Electric adds to the filter with AND, keeps free of subqueries and limits to the synced columns. Its own
 * `where`, `params` or another `table` is refused, 400: anded in, a filter that reads other tables would tell the
 * client about rows it can't read; left out, the client would get more than it asked for.
 */
import type { Problem, Queryable } from "./index.js";

/** A synced table's shape, as `rowstile client electric` writes it. */
export interface ElectricShape {
  readonly table: string;
  /** The key columns: always synced. */
  readonly keys: readonly string[];
  /** The columns the policy masks: never synced. */
  readonly masked: readonly string[];
  /** The filter for each principal type, its id the parameter $1. */
  readonly where: { readonly [principalType: string]: string };
}

/** Whom a shape is for: who the request signed in as (id null: nobody), and whether the session is limited, by
 *  scopes (a key's, a token's) or by viewing as someone (authz.session_limited()). */
export interface SyncPrincipal {
  readonly type: string;
  readonly id: string | null;
  readonly limited: boolean;
}

// (authz.session_limited() believes the settings only when signed, as authz.principal() does: a session that set
// them by hand gets an error)
const WHO = "SELECT p.principal_type, p.principal_id, authz.session_limited() AS limited " +
  "FROM (SELECT 1) one LEFT JOIN authz.principal() p ON true";

/** Who the transaction q is signed in as, for a shape: call it in a transaction signed in the app's way. */
export async function syncPrincipal(q: Queryable): Promise<SyncPrincipal> {
  const row = (await q.query(WHO, [])).rows[0] as { principal_type: string | null; principal_id: string | null; limited: boolean };
  return { type: row.principal_type ?? "user", id: row.principal_id, limited: row.limited };
}

export interface ElectricShapeOptions {
  /** Electric's shape endpoint, http://electric:3000/v1/shape: where the request goes, never where the client says. */
  url: string | URL;
  /** Electric's secret (ELECTRIC_SECRET), sent as its `secret` parameter. */
  secret?: string;
  /** Who the request is, asked of the database the app's way: syncPrincipal(c) in a transaction signed in as the
   *  request's user (a session, a key: authz.login_key, a token: authz.login_jwt). */
  signedIn(req: Request): Promise<SyncPrincipal>;
  /** The request headers that tell one user from another (the session's cookie, authorization): the answer varies
   *  on them, so a cache never gives one user's shape to another. */
  vary: readonly string[];
  /** The columns to sync, the key columns with them; every column when not given. A table the policy masks a
   *  column of needs them, leaving it out. */
  columns?: readonly string[];
  /** fetch, to reach Electric (the global one when not given). */
  fetch?: typeof fetch;
}

// what a client may send: Electric's protocol (where it is in the shape's log, live or not) and its subsets, which
// Electric adds to the filter with AND
const PROTOCOL = new Set(["offset", "handle", "live", "live_sse", "experimental_live_sse", "cursor", "expired_handle",
  "log", "replica", "cache-buster", "subset__where", "subset__params", "subset__limit", "subset__offset",
  "subset__order_by", "subset__where_expr", "subset__order_by_expr"]);
// what defines the shape: the server's alone
const DEFINITION = /^(where|params(\[.*\])?|queryable_columns|secret|api_secret)$/;
// a POST's body: a subset, nothing more
const SUBSET = new Set(["where", "params", "limit", "offset", "order_by", "where_expr", "order_by_expr"]);

/** "id","name": each column quoted, as Electric's columns take them. */
const quoted = (columns: readonly string[]) => columns.map((c) => '"' + c.replace(/"/g, '""') + '"').join(",");

/** The names in Electric's columns parameter: quoted as written, unquoted folded to lower case, as Postgres reads
 *  them; undefined for a list it can't read. */
function names(text: string): string[] | undefined {
  const out: string[] = [];
  const name = /\s*(?:"((?:[^"]|"")*)"|([^",\s]+))\s*(,|$)/y;
  while (name.lastIndex < text.length) {
    const m = name.exec(text);
    if (!m) return undefined;
    out.push(m[1] !== undefined ? m[1].replace(/""/g, '"') : m[2]!.toLowerCase());
    if (!m[3]) break;
  }
  return out;
}

function problem(status: number, title: string, type: string, detail: string, code: string, vary: string): Response {
  const body: Problem = { type: `https://rowstile.dev/problems/${type}`, title, status, detail, code };
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/problem+json", "cache-control": "no-store", vary },
  });
}

/** A route that answers the shape requests of one synced table (GET, and POST for a subset), as the signed-in user. */
export function electricShape(shape: ElectricShape, options: ElectricShapeOptions): (req: Request) => Promise<Response> {
  const { table } = shape;
  const masked = new Set(shape.masked);
  const synced = options.columns && [...new Set([...shape.keys, ...options.columns])];
  const leak = synced?.find((c) => masked.has(c));
  if (leak !== undefined) throw new Error(`rowstile: the policy masks ${table}.${leak}, which is never synced: leave it out of columns`);
  if (synced === undefined && masked.size) {
    throw new Error(`rowstile: the policy masks ${[...masked].join(", ")} of ${table}: say which columns to sync (columns: [...]), without them`);
  }
  if (!options.vary.length) throw new Error('rowstile: say which request headers tell users apart (vary: ["cookie"]), so no cache mixes them up');
  const vary = options.vary.join(", ");
  const go = options.fetch ?? fetch;
  const bad = (detail: string) => problem(400, "Bad Request", "bad-argument", detail, "AZ710", vary);
  return async (req: Request) => {
    if (req.method !== "GET" && req.method !== "POST") {
      return new Response(null, { status: 405, headers: { allow: "GET, POST", vary } });
    }
    const asked = new URL(req.url).searchParams;
    const upstream = new URL(options.url);
    let columns = synced;
    for (const [key, value] of asked) {
      if (DEFINITION.test(key)) return bad(`the shape of ${table} is the server's: a client may not set ${key} (narrow it with a subset: subset__where)`);
      if (key === "table") {
        if (value !== table) return bad(`this route syncs ${table}, not ${value}`);
      } else if (key === "columns") {
        const wanted = names(value);
        const other = wanted?.find((c) => masked.has(c) || (synced !== undefined && !synced.includes(c)));
        if (wanted === undefined || other !== undefined) {
          return bad(`${table} doesn't sync ${other ?? value}${other !== undefined && masked.has(other) ? ": the policy masks it" : ""}`);
        }
        columns = [...new Set([...shape.keys, ...wanted])];
      } else if (PROTOCOL.has(key)) {
        upstream.searchParams.append(key, value);
      }
    }
    let body: string | undefined;
    if (req.method === "POST") {
      let subset: unknown;
      try {
        subset = await req.json();
      } catch {
        return bad("a POST's body is a subset, as JSON");
      }
      const extra = subset !== null && typeof subset === "object" && !Array.isArray(subset)
        ? Object.keys(subset).find((k) => !SUBSET.has(k)) : "";
      if (extra !== undefined) return bad(`a POST's body is a subset (where, params, limit, offset, order_by): not ${extra || "that"}`);
      body = JSON.stringify(subset);
    }
    const who = await options.signedIn(req);
    if (who.id === null) {
      return problem(401, "Unauthorized", "not-signed-in", `sign in to sync ${table}`, "AZ714", vary);
    }
    if (who.limited) {
      return problem(403, "Forbidden", "refused", `a session limited by scopes, or viewing as someone, can't sync ${table}: ` +
        "the sync index holds what each principal may read, without scopes", "AZ704", vary);
    }
    const where = shape.where[who.type];
    if (where === undefined) return problem(403, "Forbidden", "refused", `${who.type} doesn't sync ${table}`, "AZ704", vary);
    upstream.searchParams.set("table", table);
    upstream.searchParams.set("where", where);
    upstream.searchParams.set("params[1]", who.id);
    if (columns) upstream.searchParams.set("columns", quoted(columns));
    if (synced) upstream.searchParams.set("queryable_columns", quoted(synced));
    if (options.secret !== undefined) upstream.searchParams.set("secret", options.secret);
    const got = await go(upstream, {
      method: req.method,
      body,
      headers: body === undefined ? {} : { "content-type": "application/json" },
      signal: req.signal,
    });
    // fetch has decoded the body already: what said how it was encoded no longer holds
    const headers = new Headers(got.headers);
    headers.delete("content-encoding");
    headers.delete("content-length");
    headers.set("vary", [...new Set([...(got.headers.get("vary") ?? "").split(","), ...options.vary]
      .map((h) => h.trim().toLowerCase()).filter(Boolean))].join(", "));
    return new Response(got.body, { status: got.status, statusText: got.statusText, headers });
  };
}

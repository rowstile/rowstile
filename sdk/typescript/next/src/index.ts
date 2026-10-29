/**
 * rowstile with Next.js (App Router).
 *
 * Importing it keeps signed-in reads out of caches: before a transaction signs in as someone, it calls
 * Next's connection(), which makes the render dynamic, and throws inside "use cache" and unstable_cache, so
 * what one user may see is never cached for another. (Reads as nobody may be cached: they are the same for
 * everyone.)
 *
 *     export const PATCH = route(async (req, { params }) => { ... });   // Refused: 403, NotFound: 404
 *     export const rename = action(async (id: number, name: string) => { ... });   // { ok, value } or { ok: false, problem }
 *     export const { GET, POST } = authzRoutes({ calls: db.$authz, changes: changes(pool) });   // for @rowstile/react
 */
import { connection } from "next/server.js";   // next has no exports map: Node needs the file name
import {
  beforeSignIn, problemOf, problemResponse, translate,
  type AuthzCalls, type Principal, type Problem,
} from "@rowstile/client";

async function keepOutOfCaches(p: Principal): Promise<void> {
  if (p.id === null) return;
  try {
    await connection();
  } catch (e) {
    // outside a request (a worker, a script, a test) and in after(), which runs once the response is sent,
    // there is no render and no cache to keep out of
    if (e instanceof Error && /outside a request scope|inside `after\(\)`/.test(e.message)) return;
    throw e;
  }
}
beforeSignIn(keepOutOfCaches);

/** For instrumentation.ts's register(): stop the server if its connection skips row-level security (a
 *  superuser, BYPASSRLS, the tables' owner), where the database would filter nothing.
 *
 *     export async function register() {
 *       if (process.env.NEXT_RUNTIME === "nodejs") await checkAtStart((await import("./db")).db.$authz);
 *     }
 *
 *  In the edge runtime it throws instead (preview): there is no server there to stop, and no process.exit. */
export async function checkAtStart(calls: { check(): Promise<void> }): Promise<void> {
  if (process.env.NEXT_RUNTIME === "edge") {
    throw new Error("rowstile: checkAtStart stops a Node.js server, and the edge runtime has none to stop: call it " +
      'in register() where NEXT_RUNTIME is "nodejs" (the edge routes connect as the same role)');
  }
  try {
    await calls.check();
  } catch (e) {
    console.error(`rowstile: ${e instanceof Error ? e.message : String(e)}`);
    // (read off process when it is called: a build of the edge runtime warns of process.exit, which it never runs)
    const { exit } = process;
    exit(1);
  }
}

/** A route handler whose refusals answer 403 with the reason, and hidden rows 404 (RFC 9457 problem bodies); a call
 *  the database turns down that is no refusal answers as its code's page says, with its words: 401 for a login
 *  refused or a call that needs someone signed in (AZ703, AZ714), 404 for something it names that isn't there
 *  (AZ708), 400 for an argument missing or wrong (AZ710), 409 for a move inside itself (AZ713). */
export function route<A extends unknown[]>(handler: (...args: A) => Response | Promise<Response>): (...args: A) => Promise<Response> {
  return async (...args: A) => {
    try {
      return await handler(...args);
    } catch (e) {
      const r = problemResponse(e);
      if (r) return r;
      throw translate(e) ?? e;
    }
  };
}

/** What a server action returns: its value, or the problem (a server action can't answer 403, and Next.js hides
 *  a thrown error's message in production). */
export type ActionResult<R> = { ok: true; value: R } | { ok: false; problem: Problem };

/** A server action whose refusals and hidden rows come back as { ok: false, problem } instead of an error, and
 *  so does what route() answers 401, 404, 400 or 409 for (AZ703, AZ714, AZ708, AZ710, AZ713). */
export function action<A extends unknown[], R>(fn: (...args: A) => Promise<R>): (...args: A) => Promise<ActionResult<R>> {
  return async (...args: A) => {
    try {
      return { ok: true, value: await fn(...args) };
    } catch (e) {
      const problem = problemOf(e);
      if (problem) return { ok: false, problem };
      throw translate(e) ?? e;
    }
  };
}

export interface RoutesOptions {
  /** The runtime's functions, each signed in as the request's user: db.$authz (Prisma), authz(pool) (pg), ... */
  calls: AuthzCalls;
  /** Subscribe to the change feed for live updates (changes(pool) from @rowstile/pg); without it, no /events. */
  changes?: (onChange: () => void) => () => void;
  /** The most event streams open at once (1000): one more answers 503. A stream tells only that something
   *  changed, to whoever asks, signed in or not; each open one holds a subscriber, so their number has a limit. */
  maxStreams?: number;
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

/** The routes @rowstile/react calls, for a catch-all route (app/api/authz/[...authz]/route.ts):
 *  GET perms?type=folder&ids=1&ids=2 (POST perms {type, ids} for a long list), GET shares?type=folder&id=3,
 *  GET events (server-sent events), POST share, POST unshare, POST request. Each answers as the signed-in
 *  user, and only what they may see. The POST routes take application/json only: a form on another site
 *  can't send that without the browser asking this one first. They answer as route() does: a share with
 *  someone who doesn't exist 404, a request for access without a reason 400, and one from someone not signed in
 *  401, with the database's words. */
export function authzRoutes(options: RoutesOptions) {
  const { calls } = options;
  const streams = { open: 0, most: options.maxStreams ?? 1000 };
  const last = (req: Request) => new URL(req.url).pathname.split("/").filter(Boolean).pop() ?? "";
  const GET = route(async (req: Request) => {
    const url = new URL(req.url);
    const type = url.searchParams.get("type") ?? "";
    switch (last(req)) {
      case "perms": {
        const ids = url.searchParams.getAll("ids");
        return json(await calls.permsOf(type as never, ids));
      }
      case "shares":
        return json(await calls.listShares(type as never, url.searchParams.get("id") ?? ""));
      case "events":
        return events(req, options.changes, streams);
      default:
        return json({ title: "Not Found", status: 404 }, 404);
    }
  });
  const POST = route(async (req: Request) => {
    if (!/^application\/json\b/i.test(req.headers.get("content-type") ?? "")) {
      return json({ title: "Unsupported Media Type", status: 415, detail: "send application/json" }, 415);
    }
    const body: unknown = await req.json();
    const b = body as Record<string, string>;
    switch (last(req)) {
      case "perms": {
        const ids = (body as { ids?: unknown }).ids;
        return json(await calls.permsOf(b.type as never, Array.isArray(ids) ? ids.map(String) : []));
      }
      case "share":
        await calls.share(b.type as never, b.id, b.relation as never, b.subjectType, b.subjectId, b.subjectRelation ?? "");
        return json({ ok: true });
      case "unshare":
        await calls.unshare(b.type as never, b.id, b.relation as never, b.subjectType, b.subjectId, b.subjectRelation ?? "");
        return json({ ok: true });
      case "request":
        return json({ id: await calls.requestAccess(b.type as never, b.id, b.relation as never, b.reason ?? "") });
      default:
        return json({ title: "Not Found", status: 404 }, 404);
    }
  });
  return { GET, POST };
}

/** Server-sent events: "changed" whenever access may have changed, so the page asks again. */
function events(req: Request, changes: ((onChange: () => void) => () => void) | undefined,
                streams: { open: number; most: number }): Response {
  if (!changes) return json({ title: "Not Found", status: 404, detail: "no change feed: authzRoutes({ changes })" }, 404);
  if (streams.open >= streams.most) {
    return json({ title: "Service Unavailable", status: 503, detail: "too many event streams open" }, 503);
  }
  const encoder = new TextEncoder();
  let stop: () => void;                             // set as the stream starts, which is at once
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      streams.open += 1;
      let counted = true;
      // a stream that ended, told of a change all the same: nothing to send, and it stops
      const send = (text: string) => {
        try {
          controller.enqueue(encoder.encode(text));
        } catch {
          stop();
        }
      };
      send(": connected\n\n");
      const unsubscribe = changes(() => send("event: changed\ndata: {}\n\n"));
      const ping = setInterval(() => send(": ping\n\n"), 25000);
      stop = () => {
        if (!counted) return;                      // once: a page that leaves cancels the stream and aborts the request
        counted = false;
        streams.open -= 1;
        clearInterval(ping);
        unsubscribe();
        try { controller.close(); } catch { /* closed already */ }
      };
      req.signal.addEventListener("abort", () => stop());
    },
    cancel() {
      stop();
    },
  });
  return new Response(stream, {
    headers: { "content-type": "text/event-stream", "cache-control": "no-cache, no-transform", connection: "keep-alive" },
  });
}

export { keepOutOfCaches };

// The world the checks start from, and what they ask of it: the database as its owner, authz.list as a user (the
// oracle), and each user's shapes through the app, live, with Electric's own client.
//
//   users   1 ann, 2 bo, 3 cy, 4 dee, 5 eve
//   teams   1 eng, 2 backend (inside eng), 3 ops        bo in backend, dee in eng, cy in ops
//   folders 1 top (ann's, given to eng), 2 inside (in top, ann's), 3 eve's, 4 ops (eve's, given to ops)
//   files   1 in top, 2 and 3 in inside, 6 in inside (shared with bo too): ann's; 4 in eve's, 5 in ops: eve's
//   notes   1 on file 2 (bo's), 2 on file 5 (cy's)
import { fileURLToPath } from "node:url";
import pg from "pg";
import { isChangeMessage, isControlMessage, Shape, ShapeStream, type ExternalParamsRecord, type Message, type Row } from "@electric-sql/client";

export const OWNER = process.env.ROWSTILE_OWNER_DSN ?? "";
export const APP = process.env.ROWSTILE_APP_URL ?? "";
export const SERVER = process.env.CONFORMANCE_SERVER ?? "";          // a pool of 5 connections
export const SERVER_ONE = process.env.CONFORMANCE_SERVER_ONE ?? "";  // a pool of one
export const CACHE = process.env.CONFORMANCE_CACHE ?? "";            // nginx, a shared cache, in front of SERVER
export const ELECTRIC = process.env.ELECTRIC_URL ?? "";              // Electric itself, which only the app reaches
export const SECRET = process.env.ELECTRIC_SECRET ?? "";
export const USERS = ["1", "2", "3", "4", "5"];
/** The index's mode test.sh set up (SYNC_MODE): copied, keyed (by folder) or after (commit), and its policy's file */
export const MODE = process.env.SYNC_MODE ?? "copied";
export const POLICY = process.env.SYNC_POLICY ?? fileURLToPath(new URL("../db/policy.authz", import.meta.url));

/** Runs fn on a connection of its own to url (the owner's, by default), then closes it. */
export async function owner<R>(fn: (c: pg.Client) => Promise<R>, url = OWNER): Promise<R> {
  const c = new pg.Client({ connectionString: url });
  await c.connect();
  try {
    return await fn(c);
  } finally {
    await c.end();
  }
}

/** SQL run as the owner, in one transaction. */
export const run = (sql: string, values: unknown[] = []) => owner((c) => c.query(sql, values));

/** SQL run as a user, signed in, in one transaction: the database's own answers, as the app would get them. */
export async function asUser<R = Row>(user: string, sql: string, values: unknown[] = []): Promise<R[]> {
  return owner(async (c) => {
    await c.query("BEGIN");
    await c.query("SELECT authz.act_as('user', $1)", [user]);
    const rows = (await c.query(sql, values)).rows as R[];
    await c.query("COMMIT");
    return rows;
  }, APP);
}

/** The oracle: the ids authz.list gives the user, of a type's objects they may view. */
export async function listed(user: string, type: string): Promise<number[]> {
  const rows = await asUser<{ x: string }>(user, "SELECT x FROM authz.list($1, 'view', NULL, NULL) x", [type]);
  return rows.map((r) => Number(r.x)).sort((a, b) => a - b);
}

export async function seed(): Promise<void> {
  if (!OWNER) throw new Error("ROWSTILE_OWNER_DSN is not set (test.sh sets it)");
  await run(`
    TRUNCATE app.notes, app.files, app.folder_teams, app.folders, app.team_members, app.teams, app.users;
    DELETE FROM authz.shares;
    DELETE FROM authz.api_keys;
    INSERT INTO app.users VALUES (1, 'ann'), (2, 'bo'), (3, 'cy'), (4, 'dee'), (5, 'eve');
    INSERT INTO app.teams VALUES (1, NULL, 'eng'), (2, 1, 'backend'), (3, NULL, 'ops');
    INSERT INTO app.team_members VALUES (2, 2), (1, 4), (3, 3);
    INSERT INTO app.folders VALUES (1, NULL, 1, 'top'), (2, 1, 1, 'inside'), (3, NULL, 5, 'eve''s'), (4, NULL, 5, 'ops');
    INSERT INTO app.folder_teams VALUES (1, 1), (4, 3);
    INSERT INTO app.files VALUES (1, 1, 1, 'a', false), (2, 2, 1, 'b', false), (3, 2, 1, 'c', false),
      (4, 3, 5, 'd', false), (5, 4, 5, 'e', false), (6, 2, 1, 'f', false);
    INSERT INTO app.notes VALUES (1, 2, 2, 'bo''s note'), (2, 5, 3, 'cy''s note');
    SELECT authz.act_as('user', '1');
    SELECT authz.share('file', '6', 'viewer', 'user', '2');`);
}

/** A request's headers as a user (a header here; a real app has its session), or nobody. */
export const as = (user: string | null, more: Record<string, string> = {}): Record<string, string> =>
  user === null ? more : { "x-user": user, ...more };

/** The ids in a response's body of shape log entries (a snapshot: inserts). */
export async function idsOf(r: Response): Promise<number[]> {
  const log = (await r.json()) as { value?: { id: string }; headers: { operation?: string } }[];
  return log.filter((m) => m.headers.operation === "insert").map((m) => Number(m.value?.id)).sort((a, b) => a - b);
}

/** The rows a shape's log gives, as a client must keep them: its inserts, updates and deletes, and the rows a
 *  move-out takes away. A filter with a subquery (the sync index's join) moves rows out with an event naming the
 *  values that no longer match (patterns, against the tags each row came with), and no delete: Electric's own Shape
 *  (@electric-sql/client 1.5.28) doesn't read those events, and would keep a row the user may no longer read, so
 *  this follows them as Electric's Elixir client does (its TagTracker), for a filter of ANDs and ORs over positions. */
class Rows {
  readonly rows = new Map<string, { value: Row; entries: Set<string>; active: boolean[] | null }>();
  private disjuncts: number[][] | null = null;

  apply(m: Message<Row>): void {
    if (isControlMessage(m)) {
      if (m.headers.control === "must-refetch") this.rows.clear();
      return;
    }
    if (isChangeMessage(m)) {
      const h = m.headers as { operation: string; tags?: string[]; removed_tags?: string[]; active_conditions?: boolean[] };
      if (h.operation === "delete") {
        this.rows.delete(m.key);
        return;
      }
      const tags = (h.tags ?? []).map((t) => t.split("/").map((x) => x || null));
      this.disjuncts ??= tags.length ? tags.map((d) => d.flatMap((x, i) => (x === null ? [] : [i]))) : null;
      const old = this.rows.get(m.key);
      const entries = new Set(old?.entries ?? []);
      for (const t of h.removed_tags ?? []) t.split("/").forEach((x, i) => x && entries.delete(`${i}:${x}`));
      tags.forEach((d) => d.forEach((x, i) => x !== null && entries.add(`${i}:${x}`)));
      if (h.operation === "update" && old && entries.size === 0 && (old.entries.size > 0)) {
        this.rows.delete(m.key);
        return;
      }
      const active = h.active_conditions?.length ? [...h.active_conditions] : null;
      this.rows.set(m.key, { value: { ...(old?.value ?? {}), ...m.value }, entries, active });
      return;
    }
    const e = m as unknown as { headers: { event: string; patterns: { pos: number; value: string }[] } };
    for (const [key, row] of this.rows) {
      const hit = e.headers.patterns.filter((p) => row.entries.has(`${p.pos}:${p.value}`));
      if (!hit.length) continue;
      if (e.headers.event === "move-in") {
        for (const p of hit) if (row.active) row.active[p.pos] = true;
      } else if (row.active && this.disjuncts) {
        for (const p of hit) row.active[p.pos] = false;
        if (!this.disjuncts.some((d) => d.every((i) => row.active![i] === true))) this.rows.delete(key);
      } else {
        for (const p of hit) row.entries.delete(`${p.pos}:${p.value}`);
        if (!row.entries.size) this.rows.delete(key);
      }
    }
  }
}

/** A user's shape of a table, through the app (or straight from Electric, given its parameters), live: the rows it
 *  holds after each batch of messages, the controls it was sent (must-refetch, a 409), and its handle. */
export class Live {
  readonly stream: ShapeStream;
  /** Electric's own Shape on the same stream, beside: what it holds, to compare (it reads each batch first) */
  readonly shape: Shape;
  readonly controls: string[] = [];
  private readonly kept = new Rows();
  private readonly stop = new AbortController();
  private readonly waiting = new Set<() => void>();
  private upToDate = false;
  private failed: unknown;

  constructor(readonly user: string, readonly table: string, url = `${SERVER}/shapes/${table}`,
              params?: ExternalParamsRecord) {
    this.stream = new ShapeStream({ url, headers: as(user), params, signal: this.stop.signal });
    this.shape = new Shape(this.stream);
    this.stream.subscribe((messages) => {
      for (const m of messages) {
        if (isControlMessage(m)) this.controls.push(m.headers.control);
        if (isControlMessage(m) && m.headers.control === "up-to-date") this.upToDate = true;
        this.kept.apply(m);
      }
      if (this.upToDate) for (const w of this.waiting) w();
    }, (e) => {
      this.failed = e;
    });
  }

  ids(): number[] {
    return [...this.kept.rows.values()].map((r) => Number(r.value.id)).sort((a, b) => a - b);
  }

  row(id: number): Row | undefined {
    return [...this.kept.rows.values()].find((r) => Number(r.value.id) === id)?.value;
  }

  /** Resolves once the shape, up to date, holds what ok says, as its messages arrive; fails the check after a while
   *  if it doesn't. */
  async until(ok: (live: Live) => boolean, what: string, ms = 30_000): Promise<void> {
    if (this.upToDate && ok(this)) return;
    await new Promise<void>((resolve, reject) => {
      const check = () => {
        if (!ok(this)) return;
        clearTimeout(timer);
        this.waiting.delete(check);
        resolve();
      };
      const timer = setTimeout(() => {
        this.waiting.delete(check);
        reject(new Error(`user ${this.user}'s ${this.table}: ${what} never came (it holds ${JSON.stringify(this.ids())}` +
          `${this.failed === undefined ? "" : `; the stream failed: ${String(this.failed)}`})`));
      }, ms);
      this.waiting.add(check);
    });
  }

  /** Resolves once the shape holds exactly these ids. */
  holds(ids: number[], ms?: number): Promise<void> {
    return this.until((l) => JSON.stringify(l.ids()) === JSON.stringify(ids), `the ids ${JSON.stringify(ids)}`, ms);
  }

  /** The ids Electric's own Shape holds. */
  shapeIds(): number[] {
    return this.shape.currentRows.map((r) => Number(r.id)).sort((a, b) => a - b);
  }

  close(): void {
    this.stop.abort();
    this.shape.unsubscribeAll();
    this.stream.unsubscribeAll();
  }
}

/** Electric's own parameters for a user's shape of a table, as the app's proxy sets them: to ask Electric itself. */
export function direct(table: string, where: string, user: string): ExternalParamsRecord {
  return { table, where, params: { "1": user }, secret: SECRET };
}

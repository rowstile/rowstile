// The world the checks start from, and what they ask of it: the database as its owner, authz.list as a user (the
// oracle), and each user's queries through zero-cache, live, with Zero's own client (in memory, in Node).
//
//   users   1 ann, 2 bo, 3 cy, 4 dee, 5 eve
//   teams   1 eng, 2 backend (inside eng), 3 ops        bo in backend, dee in eng, cy in ops
//   folders 1 top (ann's, given to eng), 2 inside (in top, ann's), 3 eve's, 4 ops (eve's, given to ops)
//   files   1 in top, 2 and 3 in inside, 6 in inside (shared with bo too): ann's; 4 in eve's, 5 in ops: eve's
//   notes   1 on file 2 (bo's), 2 on file 5 (cy's)
import { fileURLToPath } from "node:url";
import pg from "pg";
import { Zero } from "@rocicorp/zero";
import { mutators } from "../src/mutators.js";
import { queries } from "../src/queries.js";
import { schema, zql } from "../src/schema.js";

export const OWNER = process.env.ROWSTILE_OWNER_DSN ?? "";
export const ADMIN = process.env.ROWSTILE_ADMIN_DSN ?? "";
export const APP = process.env.ROWSTILE_APP_URL ?? "";
export const SERVER = process.env.CONFORMANCE_SERVER ?? "";   // the app, whose endpoints zero-cache calls
export const ZERO = process.env.ZERO_URL ?? "";               // zero-cache, which the clients connect to
export const USERS = ["1", "2", "3", "4", "5"];
/** The index's mode test.sh set up (SYNC_MODE): copied, keyed (by folder) or after (commit), and its policy's file */
export const MODE = process.env.SYNC_MODE ?? "copied";
export const POLICY = process.env.SYNC_POLICY ?? fileURLToPath(new URL("../db/policy.authz", import.meta.url));
export const TABLES = { file: "files", folder: "folders", note: "notes" } as const;
export type Kind = keyof typeof TABLES;

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

/** The oracle: the ids authz.list gives the user, of a type's objects they may view. */
export async function listed(user: string, type: Kind): Promise<number[]> {
  return owner(async (c) => {
    await c.query("BEGIN");
    await c.query("SELECT authz.act_as('user', $1)", [user]);
    const rows = (await c.query("SELECT x FROM authz.list($1, 'view', NULL, NULL) x", [type])).rows as { x: string }[];
    await c.query("COMMIT");
    return rows.map((r) => Number(r.x)).sort((a, b) => a - b);
  }, APP);
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

type Row = { readonly id: number; readonly [column: string]: unknown };
/** A Zero client, in memory, at zero-cache: its type as Zero infers it. */
function zeroClient(userID: string, auth: string | undefined, context: { type: "user"; id: string }) {
  return new Zero({ server: ZERO, userID, auth, schema, mutators, kvStore: "mem", context });
}
type ZeroClient = ReturnType<typeof zeroClient>;
/** The part of a materialized view the checks use. */
interface View {
  addListener(listener: (data: unknown, resultType: string) => void): unknown;
  destroy(): void;
}

/** A user's Zero client, live: what each of its queries holds now, and a wait for it to hold what's expected. */
export class Client {
  readonly zero: ZeroClient;
  readonly rows: Record<Kind, number[]> = { file: [], folder: [], note: [] };
  readonly data: Record<Kind, readonly Row[]> = { file: [], folder: [], note: [] };
  readonly complete: Record<Kind, boolean> = { file: false, folder: false, note: false };
  private readonly views: View[] = [];
  private readonly waiters = new Set<() => void>();

  /** token: what the client sends as its auth (a user's id, key:<secret>), or null; context: what it says it is. */
  constructor(readonly token: string | null, context: { type: "user"; id: string } | undefined = undefined, userID?: string) {
    const id = userID ?? token ?? "nobody";
    this.zero = zeroClient(id, token ?? undefined, context ?? { type: "user", id });
    this.watch("file", this.zero.materialize(queries.files()));
    this.watch("folder", this.zero.materialize(queries.folders()));
    this.watch("note", this.zero.materialize(queries.notes()));
  }

  /** What a query's view holds, as it changes. */
  private watch(kind: Kind, view: View): void {
    view.addListener((data, resultType) => {
      this.data[kind] = [...(data as readonly Row[])];
      this.rows[kind] = this.data[kind].map((r) => r.id);
      this.complete[kind] = resultType === "complete";
      for (const w of this.waiters) w();
    });
    this.views.push(view);
  }

  /** Resolves once the query of kind holds exactly ids, from the server; fails after ms with what it held. */
  async holds(kind: Kind, ids: number[], ms = 30_000): Promise<void> {
    const want = [...ids].sort((a, b) => a - b).join(",");
    const now = () => this.complete[kind] && [...this.rows[kind]].sort((a, b) => a - b).join(",") === want;
    if (now()) return;
    await new Promise<void>((resolve, reject) => {
      const done = () => {
        if (!now()) return;
        clearTimeout(timer);
        this.waiters.delete(done);
        resolve();
      };
      const timer = setTimeout(() => {
        this.waiters.delete(done);
        reject(new Error(`${kind} of ${this.token}: [${this.rows[kind].join(",")}] (complete: ${this.complete[kind]}), want [${want}]`));
      }, ms);
      this.waiters.add(done);
    });
  }

  /** The row of kind with that id the query holds now, if it does. */
  row(kind: Kind, id: number): Row | undefined {
    return this.data[kind].find((r) => r.id === id);
  }

  /** Resolves once ok() holds of what the queries hold; fails after ms, saying what. */
  async until(ok: () => boolean, what: string, ms = 30_000): Promise<void> {
    if (ok()) return;
    await new Promise<void>((resolve, reject) => {
      const done = () => {
        if (!ok()) return;
        clearTimeout(timer);
        this.waiters.delete(done);
        resolve();
      };
      const timer = setTimeout(() => {
        this.waiters.delete(done);
        reject(new Error(`${what}, for ${this.token}: never seen`));
      }, ms);
      this.waiters.add(done);
    });
  }

  /** The ids of a table the client's own store holds (synced to it, whatever its queries show), once they are ids. */
  async stored(kind: Kind, ids: number[], ms = 30_000): Promise<number[]> {
    const want = [...ids].sort((a, b) => a - b).join(",");
    const deadline = Date.now() + ms;
    let got: number[] = [];
    while (Date.now() < deadline) {
      const rows: readonly Row[] = kind === "file" ? await this.zero.run(zql.file)
        : kind === "folder" ? await this.zero.run(zql.folder) : await this.zero.run(zql.note);
      got = rows.map((r) => r.id).sort((a, b) => a - b);
      if (got.join(",") === want) return got;
      await new Promise((r) => setTimeout(r, 100));
    }
    return got;
  }

  /** Resolves once every query holds what authz.list gives its user now. */
  async listed(ms = 30_000): Promise<void> {
    for (const kind of Object.keys(TABLES) as Kind[]) await this.holds(kind, await listed(this.token ?? "", kind), ms);
  }

  /** The connection's state as Zero names it (connected, needs-auth, ...), once it is name, or after ms. */
  async state(name: string, ms = 30_000): Promise<string> {
    const deadline = Date.now() + ms;
    while (Date.now() < deadline) {
      const s = this.zero.connection.state.current.name;
      if (s === name) return s;
      await new Promise((r) => setTimeout(r, 100));
    }
    return this.zero.connection.state.current.name;
  }

  async close(): Promise<void> {
    for (const v of this.views) v.destroy();
    await this.zero.close();
  }
}

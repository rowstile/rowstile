// The world the checks start from, and what they ask of it: the database as its owner, authz.list as a user (the
// oracle), and each user's PowerSync client, live, in Node (@powersync/node on better-sqlite3).
//
//   users   1 ann, 2 bo, 3 cy, 4 dee, 5 eve
//   teams   1 eng, 2 backend (inside eng), 3 ops        bo in backend, dee in eng, cy in ops
//   folders 1 top (ann's, given to eng), 2 inside (in top, ann's), 3 eve's, 4 ops (eve's, given to ops)
//   files   1 in top, 2 and 3 in inside, 6 in inside (shared with bo too): ann's; 4 in eve's, 5 in ops: eve's
//   notes   1 on file 2 (bo's), 2 on file 5 (cy's)
import { randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { column, PowerSyncDatabase, Schema, Table, UpdateType, type AbstractPowerSyncDatabase } from "@powersync/node";

export const OWNER = process.env.ROWSTILE_OWNER_DSN ?? "";
export const ADMIN = process.env.ROWSTILE_ADMIN_DSN ?? "";
export const APP = process.env.ROWSTILE_APP_URL ?? "";
export const SERVER = process.env.CONFORMANCE_SERVER ?? "";   // the app: tokens, and the clients' writes
export const SERVICE = process.env.POWERSYNC_URL ?? "";       // the PowerSync service, which the clients sync from
export const USERS = ["1", "2", "3", "4", "5"];
/** The index's mode test.sh set up (SYNC_MODE): copied or after (commit), and its policy's file */
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

// the client's tables, as the streams give them (PowerSync keeps each row's id as text)
const schema = new Schema({
  files: new Table({ folder_id: column.integer, owner_id: column.integer, name: column.text, confidential: column.integer }),
  folders: new Table({ parent_id: column.integer, owner_id: column.integer, name: column.text }),
  notes: new Table({ file_id: column.integer, author_id: column.integer }),
});

/** A user's PowerSync client, live: what each table holds now, and a wait for it to hold what's expected. Its token
 *  comes from the app, asked as the user (a header here: a real app has its session), or with an API key. */
export class Client {
  readonly db: PowerSyncDatabase;
  /** What the app answered when the client asked for a token: its status, for each ask. */
  readonly asked: number[] = [];
  /** The client's writes the app refused, as its problem bodies said. */
  readonly refused: string[] = [];
  private readonly ready: Promise<void>;

  constructor(readonly user: string | null, readonly key: string | null = null) {
    this.db = new PowerSyncDatabase({
      schema,
      // (a file name of its own: PowerSync locks a database by its name, so clients that shared one would wait for each other)
      database: { dbFilename: `client-${randomUUID()}.db`, dbLocation: mkdtempSync(join(tmpdir(), "ps-client-")) },
    });
    const headers: Record<string, string> = key !== null ? { "x-api-key": key } : user !== null ? { "x-user": user } : {};
    const self = this;
    this.ready = this.db.connect({
      async fetchCredentials() {
        const r = await fetch(`${SERVER}/api/powersync/token`, { method: "POST", headers });
        self.asked.push(r.status);
        if (!r.ok) return null;                                    // no token: the client doesn't sync
        return { endpoint: SERVICE, token: ((await r.json()) as { token: string }).token };
      },
      // the client's writes, sent to the app's routes as the user: what the app refuses is noted, and dropped
      async uploadData(database: AbstractPowerSyncDatabase) {
        const tx = await database.getNextCrudTransaction();
        if (!tx) return;
        for (const op of tx.crud) {
          if (op.table !== "files" || op.op !== UpdateType.PATCH) continue;
          const r = await fetch(`${SERVER}/api/files/${op.id}`, {
            method: "PATCH", headers: { ...headers, "content-type": "application/json" }, body: JSON.stringify(op.opData),
          });
          if (!r.ok) self.refused.push(`${r.status} ${JSON.stringify(await r.json())}`);
        }
        await tx.complete();
      },
    });
  }

  /** The ids a table of the client holds now. */
  async ids(kind: Kind): Promise<number[]> {
    await this.ready;
    const rows = (await this.db.getAll(`SELECT id FROM ${TABLES[kind]}`)) as { id: string }[];
    return rows.map((r) => Number(r.id)).sort((a, b) => a - b);
  }

  /** A row of a table, as the client holds it. */
  async row(kind: Kind, id: number): Promise<Record<string, unknown> | null> {
    await this.ready;
    return (await this.db.getOptional(`SELECT * FROM ${TABLES[kind]} WHERE id = ?`, [String(id)])) as Record<string, unknown> | null;
  }

  /** Resolves once ok() holds; fails after ms, saying what. */
  async until(ok: () => Promise<boolean>, what: string, ms = 30_000): Promise<void> {
    const deadline = Date.now() + ms;
    while (Date.now() < deadline) {
      if (await ok()) return;
      await new Promise((r) => setTimeout(r, 100));
    }
    throw new Error(`${what}, for ${this.user ?? this.key}: never seen`);
  }

  /** Resolves once a table holds exactly ids; fails after ms with what it held. */
  async holds(kind: Kind, ids: number[], ms = 30_000): Promise<void> {
    const want = [...ids].sort((a, b) => a - b).join(",");
    try {
      await this.until(async () => (await this.ids(kind)).join(",") === want, kind, ms);
    } catch {
      throw new Error(`${kind} of ${this.user ?? this.key}: [${(await this.ids(kind)).join(",")}], want [${want}]`);
    }
  }

  /** Resolves once every table holds what authz.list gives its user now. */
  async listed(ms = 30_000): Promise<void> {
    for (const kind of Object.keys(TABLES) as Kind[]) await this.holds(kind, await listed(this.user ?? "", kind), ms);
  }

  /** Every row the client was synced, as PowerSync keeps it (its data, the columns the stream selected). */
  async synced(): Promise<{ type: string; data: Record<string, unknown> }[]> {
    await this.ready;
    const rows = (await this.db.getAll("SELECT row_type AS type, data FROM ps_oplog")) as { type: string; data: string | null }[];
    return rows.filter((r) => r.data !== null).map((r) => ({ type: r.type, data: JSON.parse(r.data!) as Record<string, unknown> }));
  }

  async close(): Promise<void> {
    await this.db.close();
  }
}

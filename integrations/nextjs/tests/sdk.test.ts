// The SDK's own calls, each way they can go, beyond the conformance checks (conformance.test.ts): what each
// promises, asked of the database where there is one to ask. test.sh measures what these and the other checks run
// of the SDK (sdk/typescript/*/src), and fails unless they run every line, branch and function of it.
import { EventEmitter } from "node:events";
import pg from "pg";
import postgres from "postgres";
import { drizzle } from "drizzle-orm/node-postgres";
import { sql as sqlTag } from "drizzle-orm";
import { afterAll, beforeEach, describe, expect, test, vi } from "vitest";
import {
  actAsSql, actingAs, beforeSignIn, changed, current, dbError, describe as describePrincipal, errorCode, idShown, idText,
  literal, NOBODY, NotFound, principal, problemOf, problemResponse, Refused, refusal, verdict,
} from "@rowstile/client";
import { authz as rowstile, calls, changes } from "@rowstile/pg";
import { authz as postgresAuthz, queryable as postgresQueryable } from "@rowstile/postgres";
import { queryable as drizzleQueryable, withAuthz } from "@rowstile/drizzle";
import { asUser, databasePerWorker, matchers, workerId } from "@rowstile/vitest";
import { PrismaPg } from "@prisma/adapter-pg";
import { authz, signedIn } from "@rowstile/prisma";
import { PrismaClient } from "@/generated/prisma/client.ts";
import { PrismaClient as PlainClient } from "@/generated/plain/client.ts";
import { db, pool } from "@/db";
import { APP, FEED, OWNER, seed } from "./data";

beforeEach(seed);
afterAll(async () => {
  await pool.end();
  await db.$disconnect();
});

const PROJECTS = "SELECT id FROM app.projects ORDER BY id";   // ann (1) and cy (3) see 1 and 3, bo (2) 2 and 3, nobody 3
const REFUSED = "permission denied: user 3 may not update row 1 of app.notes";   // cy may edit note 4, not note 1

describe("@rowstile/client", () => {
  test("ids and principals, as the database writes them", () => {
    expect(idText([1, 'a"b\\c'])).toBe('("1","a\\"b\\\\c")');
    expect(idShown([1, null, undefined] as never)).toBe("(1,,)");          // an empty field, as Postgres writes it
    expect(principal({ type: "service", id: 3 } as never)).toEqual({ type: "service", id: "3" });
    expect(principal({ id: "4" } as never)).toEqual({ type: "user", id: "4" });   // a type left out: a user
    expect(principal({ type: "service", id: null })).toEqual({ type: "service", id: null });
    expect(principal(["service", null])).toEqual({ type: "service", id: null });
    // only no id at all is nobody: an empty one is a user's all the same, as act_as takes it
    expect([NOBODY, principal(42), principal(["service", 3]), principal("")].map(describePrincipal))
      .toEqual(["nobody", "42", "service:3", ""]);
    expect(actAsSql(NOBODY)).toBe("SELECT authz.act_as(NULL, NULL)");
    expect(actAsSql(principal("o'k"))).toBe("SELECT authz.act_as('user', 'o''k')");
    expect(literal(null)).toBe("NULL");
    expect(actingAs(3, () => current())).toEqual({ type: "user", id: "3" });   // a function that returns at once
  });

  test("errors, as a problem body and as a response", async () => {
    const share = new Refused("you cannot share project 1", undefined, undefined, [], { code: "AZ705" });
    expect(share.problem()).toMatchObject({ status: 403, detail: "you cannot share project 1", table: null, command: null, code: "AZ705" });
    expect([new NotFound().message, new NotFound("app.notes").message]).toEqual(["the row not found", "app.notes not found"]);
    const r = problemResponse(share);
    expect([r?.status, r?.headers.get("content-type"), (await r?.json()).code]).toEqual([403, "application/problem+json", "AZ705"]);
    expect([problemResponse(new Error("the app's")), problemOf(new Error("the app's"))]).toEqual([null, null]);
  });

  test("what a driver kept of an error", () => {
    expect(dbError({ code: "42501" })).toMatchObject({ code: "42501", message: "" });
    // the code is read where the runtime puts it, "rowstile help AZnnn"; an applying error's "[AZ612]" is no answer
    expect([errorCode({ code: "P0001", message: "no", hint: "rowstile help AZ612" }), errorCode({ code: "P0001", message: "a check said no [AZ612]" })])
      .toEqual(["AZ612", undefined]);
    // a column rule's words, with no table in them: the rule's code, nothing made up
    const nameless = refusal({ code: "42501", message: "changing locked of  needs: folder.manage", hint: "rowstile help AZ709" });
    expect([nameless?.table, nameless?.command, nameless?.code]).toEqual([undefined, undefined, "AZ709"]);
  });

  test("what counts as a changed row, and what one that didn't change was", () => {
    expect([changed(1n), changed(0n), changed({ rows: [{}] }), changed({ rows: [] }), changed(true), changed(undefined)])
      .toEqual([true, false, true, false, true, false]);
    expect(changed({ command: "UPDATE" })).toBe(true);                       // a result it can't read: not asked about
    const refused = verdict("app.notes", "update", 1, []);                   // no reason given, nobody signed in
    expect(refused.message).toBe("permission denied: someone not signed in may not update row 1 of app.notes");
    expect(actingAs(3, () => verdict("app.notes", "update", 1, ["no   update : edit"]).message)).toBe(REFUSED);
  });
});

describe("the runtime's functions over pg", () => {
  test("lists by the page, shares, access requests, a rule explained", async () => {
    const p = new pg.Pool({ connectionString: APP });
    const a = rowstile(p);
    try {
      expect(await actingAs("1", () => a.list("project", "view", { limit: 1 }))).toEqual(["1"]);
      expect(await actingAs("1", () => a.list("project", "view", { after: 1, limit: 5 }))).toEqual(["3"]);
      expect(await actingAs("1", () => a.perms("project", 999))).toEqual([]);   // no such project
      await actingAs("1", () => a.share("project", 1, "viewer", "user", 2));
      const shares = await actingAs("1", () => a.listShares("project", 1));
      expect(shares.map((s) => [s.relation, s.subject_type, s.subject_id])).toEqual([["viewer", "user", "2"]]);
      expect(await actingAs("3", () => a.requestAccess("project", 2, "viewer", "for the review"))).toMatch(/^\d+$/);
      expect(await actingAs("3", () => a.explainRule("app.notes", "update", 2))).toBeNull();   // bo's: hidden from cy
      const insert = await actingAs("2", () => a.explainRule("app.notes", "insert", undefined, { project_id: 3, author_id: 2, body: "hi" }));
      expect(insert?.[0]).toMatch(/^no   insert : project\.edit and author/);
      // and a row the rule allows (bo's own project): the answer is about the row given
      const own = await actingAs("2", () => a.explainRule("app.notes", "insert", undefined, { project_id: 2, author_id: 2, body: "hi" }));
      expect(own?.[0]).toMatch(/^yes  insert : project\.edit and author/);
    } finally {
      await p.end();
    }
  });

  test("an update that changed a row is returned; why one would not, with the new values", async () => {
    const p = new pg.Pool({ connectionString: APP });
    try {
      await actingAs("3", () => rowstile(p).transaction(async (c) => {
        const r = await c.query("UPDATE app.notes SET body = body WHERE id = 4");
        expect(await calls(c).expect(r, "app.notes", "update", 4)).toBe(r);
        const why = await calls(c).verdict("app.notes", "update", 1, { body: "x" });
        expect([why.message, why instanceof Refused && why.why.includes("after the change:")]).toEqual([REFUSED, true]);
      }));
    } finally {
      await p.end();
    }
  });

  test("who the request is when nothing set it, and a hook given twice runs once", async () => {
    let hooked = 0;
    const hook = () => { hooked += 1; };
    beforeSignIn(hook);
    beforeSignIn(hook);
    const p = new pg.Pool({ connectionString: APP });
    const ids = (c: pg.PoolClient) => c.query(PROJECTS).then((r) => r.rows.map((row) => row.id));
    try {
      const a = rowstile(p, { user: async () => "2" });
      expect(await a.transaction(ids)).toEqual([2, 3]);                     // user() says who
      expect(hooked).toBe(1);
      expect(await actingAs(null, () => a.transaction(ids))).toEqual([3]);  // actingAs decides first, null too
    } finally {
      await p.end();
    }
  });

  test("the sign-in with its values written in, for an API that takes no parameters", async () => {
    const c = new pg.Client({ connectionString: APP });
    await c.connect();
    try {
      await c.query("BEGIN");
      await c.query(actAsSql(principal(2)));
      expect((await c.query(PROJECTS)).rows.map((r) => r.id)).toEqual([2, 3]);
    } finally {
      await c.query("ROLLBACK");
      await c.end();
    }
  });

  // ids holding a backslash, a quote, both, and more: each must stay one string whatever standard_conforming_strings
  // says; the first one, if its backslash ended the string, would go on to sign in as user 1
  const AWKWARD_IDS = ["x\\'); SELECT authz.act_as($$user$$, $$1$$); --", "\\'", "\\", "'", "o''k\\\\", "ünï 字 \\n ☃"];
  test.each(["off", "on"])("an id written into the sign-in is that id, standard_conforming_strings %s", async (conforming) => {
    const c = new pg.Client({ connectionString: APP, options: `-c standard_conforming_strings=${conforming}` });
    await c.connect();
    try {
      expect((await c.query("SHOW standard_conforming_strings")).rows[0].standard_conforming_strings).toBe(conforming);
      for (const awkward of AWKWARD_IDS) {
        await c.query("BEGIN");
        await c.query(actAsSql(principal(awkward)));   // one simple statement, as pg sends a query without values
        expect((await c.query("SELECT current_setting('authz.user_id') AS id")).rows[0].id).toBe(awkward);
        await c.query("ROLLBACK");
      }
    } finally {
      await c.end();
    }
  });

  test("an insert the user may not read back, over pg: the select rule's doing", async () => {
    const p = new pg.Pool({ connectionString: APP });
    try {
      const e = await actingAs("1", () => rowstile(p).query(
        "INSERT INTO app.inbox (sender_id, recipient_id, body) VALUES (1, 2, 'hi') RETURNING id")).catch((err) => err);
      expect(e).toBeInstanceOf(Refused);
      expect([e.table, e.command]).toEqual(["inbox", "select"]);   // Postgres names no schema for it, nor does pg
      expect(e.message).toContain("this user may not see the row as written (the select rule)");
    } finally {
      await p.end();
    }
  });

  // Postgres's own words, where no rule's refusal speaks first, read for what refused: an update after which the row
  // would be hidden is the select rule's, and no read back; an upsert of a row the user may not change is the update
  // rule's; MERGE's names no command, since Postgres doesn't say whether the update rule or the delete rule
  test("Postgres's own refusals, over pg: the rule each names", async () => {
    const p = new pg.Pool({ connectionString: APP });
    // cy (3): author of note 4 in project 1, a member there
    const refused = (sql: string) => actingAs("3", () => rowstile(p).query(sql)).catch((e: unknown) => e);
    try {
      const hidden = await refused("UPDATE app.notes SET project_id = 2 WHERE id = 4");   // into bo's project
      const upsert = await refused("INSERT INTO app.notes (id, project_id, author_id, body) VALUES (1, 1, 3, 'x') " +
        "ON CONFLICT (id) DO UPDATE SET body = 'x'");                                       // note 1 is ann's
      const merge = await refused(
        "MERGE INTO app.notes n USING (VALUES (1)) s(id) ON n.id = s.id WHEN MATCHED THEN UPDATE SET body = 'x'");
      const read = (r: unknown) => r instanceof Refused ? [r.table, r.command, r.why, r.message] : r;
      expect(read(hidden)).toEqual(["notes", "select", [],
        'new row violates row-level security policy for table "notes": this user may not see the row as written ' +
        "(the select rule). An insert that reads it back (RETURNING), an upsert, and an update with a WHERE need to " +
        "see it."]);
      expect(read(upsert)).toEqual(["notes", "update", [],
        'new row violates row-level security policy (USING expression) for table "notes": the row is there already, ' +
        "and the update rule (or the select rule) doesn't let this user change it (ON CONFLICT DO UPDATE)"]);
      expect(read(merge)).toEqual(["notes", undefined, [],
        'target row violates row-level security policy (USING expression) for table "notes": MERGE matched a row ' +
        "the update or delete rule doesn't let this user change"]);
    } finally {
      await p.end();
    }
  });
});

describe("@rowstile/pg's change feed", () => {
  const until = async (ok: () => boolean) => {
    for (let i = 0; i < 100 && !ok(); i++) await new Promise((r) => setTimeout(r, 100));
  };

  test("one connection listens for every subscriber, until the last one leaves", async () => {
    const feed = new pg.Pool({ connectionString: FEED, max: 5 });
    const a = rowstile(pool);
    const told = { first: 0, second: 0, third: 0 };
    try {
      const subscribe = changes(feed);
      const first = subscribe(() => { told.first += 1; });
      const second = subscribe(() => { told.second += 1; });                // while it begins to listen
      await until(() => told.first > 0 && told.second > 0);
      const third = subscribe(() => { told.third += 1; });                  // while it listens
      expect([told.first, told.second, told.third, feed.totalCount]).toEqual([1, 1, 0, 1]);
      first();
      third();
      await actingAs("1", () => a.share("project", 1, "viewer", "user", 2));
      await until(() => told.second > 1);
      expect([told.first, told.second, told.third]).toEqual([1, 2, 0]);     // the ones still there
      second();
      await until(() => feed.idleCount === 1);                               // the last one gone: back in the pool
      expect(feed.idleCount).toBe(1);
    } finally {
      await feed.end();
    }
  });

  test("a subscriber that leaves before it listens, and a database it can't reach", async () => {
    const feed = new pg.Pool({ connectionString: FEED, max: 1 });
    let told = 0;
    try {
      changes(feed)(() => { told += 1; })();                                 // gone at once: nobody to tell
      await until(() => feed.totalCount === 1 && feed.idleCount === 1);
      expect([told, feed.idleCount]).toEqual([0, 1]);
    } finally {
      await feed.end();
    }
    let tries = 0;
    const nowhere = { connect: async () => { tries += 1; throw new Error("connect ECONNREFUSED"); } } as unknown as pg.Pool;
    changes(nowhere)(() => { told += 1; })();                                 // gone before it failed: never again
    await new Promise((r) => setTimeout(r, 700));
    expect(tries).toBe(1);
    const leave = changes(nowhere)(() => { told += 1; });
    await new Promise((r) => setTimeout(r, 700));                             // it tries again after 500 ms
    expect(tries).toBe(3);
    leave();                                                                  // ... until the last one leaves
    await new Promise((r) => setTimeout(r, 1200));
    expect([tries, told]).toEqual([3, 0]);
  });

  test("a connection lost while it begins to listen, one that ends, an UNLISTEN that fails", async () => {
    // a pool of one client the test drives: what a server can't be made to do on cue
    class Client extends EventEmitter {
      released: (string | undefined)[] = [];
      answers: Promise<unknown>[] = [];
      query(): Promise<unknown> {
        return this.answers.shift() ?? Promise.resolve();
      }
      release(e?: Error): void {
        this.released.push(e?.message);
      }
    }
    const later = () => {
      let settle = (_e?: Error) => {};
      const p = new Promise<unknown>((ok, no) => { settle = (e) => (e ? no(e) : ok(undefined)); });
      return { p, settle };
    };
    const feed = (client: Client) => changes({ connect: async () => client } as unknown as pg.Pool);
    let told = 0;
    const tell = () => { told += 1; };

    const lost = new Client();
    const listen = later();
    lost.answers.push(listen.p);
    const leave = feed(lost)(tell);
    await new Promise((r) => setTimeout(r, 10));
    lost.emit("error", new Error("connection terminated"));                  // while LISTEN is on its way
    listen.settle();
    await new Promise((r) => setTimeout(r, 10));
    leave();                                                                 // (before it tries again)
    expect([told, lost.released]).toEqual([0, ["connection terminated"]]);

    const refused = new Client();
    const denied = later();
    refused.answers.push(denied.p);
    const leaveRefused = feed(refused)(tell);
    await new Promise((r) => setTimeout(r, 10));
    denied.settle(new Error("permission denied to listen"));                  // LISTEN itself fails
    await new Promise((r) => setTimeout(r, 10));
    leaveRefused();
    expect([told, refused.released]).toEqual([0, ["permission denied to listen"]]);   // given back as broken

    const ended = new Client();
    const next = new Client();
    const clients = [ended, next];
    const leaveEnded = changes({ connect: async () => clients.shift() } as unknown as pg.Pool)(tell);
    await new Promise((r) => setTimeout(r, 10));
    expect(told).toBe(1);                                                    // listening: told once
    ended.emit("end");                                                       // closed, without an error
    expect(ended.released).toEqual(["the connection ended"]);
    await until(() => told === 2);                                           // it listens again, 500 ms later,
    expect([clients.length, told]).toEqual([0, 2]);                          // and tells what changed meanwhile
    leaveEnded();
    await new Promise((r) => setTimeout(r, 10));
    expect([ended.released, next.released]).toEqual([["the connection ended"], [undefined]]);   // back in the pool

    const stuck = new Client();
    const unlisten = later();
    stuck.answers.push(Promise.resolve(), unlisten.p);
    const leaveStuck = feed(stuck)(tell);
    await new Promise((r) => setTimeout(r, 10));
    leaveStuck();                                                            // UNLISTEN, on a connection that breaks
    stuck.emit("error", new Error("connection terminated"));                 // (no one else listens: not the process's)
    unlisten.settle(new Error("connection terminated"));
    await new Promise((r) => setTimeout(r, 10));
    expect(stuck.released).toEqual(["connection terminated"]);              // back in the pool as broken
  });
});

describe("postgres.js and Drizzle", () => {
  test("an error that isn't rowstile's stays the driver's", async () => {
    const sql = postgres(APP, { max: 1 });
    const p = new pg.Pool({ connectionString: APP });
    try {
      const notOurs = (e: unknown) => (e as { code?: string }).code;
      expect(notOurs(await postgresAuthz(sql).begin((tx) => tx`SELECT 1/0`).catch((e) => e))).toBe("22012");
      expect(notOurs(await withAuthz(drizzle(p)).transaction((tx) => tx.execute(sqlTag`SELECT 1/0`)).catch((e) => e.cause ?? e))).toBe("22012");
      expect(await postgresAuthz(sql).begin((tx) => postgresQueryable(tx).query("SELECT 2 AS two"))).toMatchObject({ rows: [{ two: 2 }] });
    } finally {
      await sql.end();
      await p.end();
    }
  });

  test("a Drizzle driver whose result holds neither rows nor a count", async () => {
    const q = drizzleQueryable({ execute: async () => ({}) });
    expect(await q.query("SELECT 1")).toEqual({ rows: [], rowCount: 0 });
  });
});

describe("@rowstile/prisma", () => {
  test("a read that must find a row names it only by its key", async () => {
    const missing = (e: unknown) => (e instanceof NotFound ? e.message : String(e));
    const first = (where: object) => actingAs("2", () => db.note.findFirstOrThrow({ where: where as never })).catch(missing);
    expect(await first({ id: 1 })).toBe("app.notes 1 not found");
    // findFirst's where is any filter: a value in it isn't a row's key
    expect(await first({ id: { gt: 100000 } })).toBe("app.notes not found");
    expect(await first({ body: "nope" })).toBe("app.notes not found");
    expect(await first({ body: { contains: "zzz" } })).toBe("app.notes not found");
    expect(await actingAs(null, () => db.message.findFirstOrThrow()).catch(missing)).toBe("app.inbox not found");
    // findUnique's is a key: of several columns too; with more than the key, it names none
    const member = await actingAs("2", () =>
      db.member.findUniqueOrThrow({ where: { project_id_user_id: { project_id: 9, user_id: 9 } } })).catch(missing);
    expect(member).toBe("app.members (9,9) not found");
    // in the key's own order (its name's: project_id_user_id), whatever order the where gives its fields in; a key
    // with a name of its own doesn't say, and names none
    const reversed = await actingAs("2", () =>
      db.member.findUniqueOrThrow({ where: { project_id_user_id: { user_id: 9, project_id: 8 } } })).catch(missing);
    expect(reversed).toBe("app.members (8,9) not found");
    const named = await actingAs("2", () =>
      db.projectService.findUniqueOrThrow({ where: { link: { project_id: 8, service_id: 9 } } })).catch(missing);
    expect(named).toBe("app.project_services not found");
    const more = await actingAs("2", () =>
      db.member.findUniqueOrThrow({ where: { project_id_user_id: { project_id: 9, user_id: 9 }, user_id: 9 } })).catch(missing);
    expect(more).toBe("app.members not found");
  });

  test("an app on Prisma's defaults: tables named without their schema, a key not called id, one with a date", async () => {
    const own = new pg.Pool({ connectionString: APP, max: 2 });
    const plain = new PlainClient({ adapter: signedIn(new PrismaPg(own)) }).$extends(authz());
    const missing = (e: unknown) => (e instanceof NotFound ? e.message : String(e));
    try {
      // no @@map, no @@schema: the model's name, found on the search_path; its key is the where's one field
      expect(await actingAs("2", () => plain.holiday.findUniqueOrThrow({ where: { code: "xmas" } })).catch(missing))
        .toBe("public.holiday xmas not found");
      // a key that is a date, or has one among its fields, which the SDK can't write as the database does: the
      // table alone
      const day = new Date("2026-12-25");
      for (const where of [{ day }, { country_day: { country: "fr", day } }]) {
        expect(await actingAs("2", () => plain.holiday.findUniqueOrThrow({ where })).catch(missing)).toBe("public.holiday not found");
      }
      // a refusal on a table this app's schema doesn't model: as the database's words name it
      const sent = await actingAs("1", () => plain.$queryRawUnsafe(
        "INSERT INTO app.inbox (sender_id, recipient_id, body) VALUES (1, 2, 'hi') RETURNING id")).catch((e: unknown) => e);
      expect(sent instanceof Refused && [sent.table, sent.command]).toEqual(["inbox", "select"]);
    } finally {
      await plain.$disconnect();
      await own.end();
    }
  });

  test("inside a transaction, the table is looked up through it", async () => {
    // a pool of one, which the transaction holds: a lookup outside it would get no connection
    const one = new pg.Pool({ connectionString: APP, max: 1, connectionTimeoutMillis: 200 });
    const plain = new PlainClient({ adapter: signedIn(new PrismaPg(one)) }).$extends(authz());
    try {
      const e = await actingAs("2", () =>
        plain.$transaction((tx) => tx.holiday.findUniqueOrThrow({ where: { code: "xmas" } }))).catch((err) => err);
      expect([e instanceof NotFound, e.message]).toEqual([true, "public.holiday xmas not found"]);
    } finally {
      await plain.$disconnect();
      await one.end();
    }
  });

  test("a table that can't be looked up is named as the model names it", async () => {
    // who the request is can be told once only (the session ended): the lookup, in a transaction of its own after
    // the read's, can't sign in
    let asked = 0;
    const user = () => {
      if (asked++) throw new Error("the session ended");
      return "2";
    };
    const own = new pg.Pool({ connectionString: APP, max: 2 });
    const plain = new PlainClient({ adapter: signedIn(new PrismaPg(own), { user }) }).$extends(authz());
    try {
      const e = await plain.holiday.findUniqueOrThrow({ where: { code: "xmas" } }).catch((err) => err);
      expect([e instanceof NotFound, e.message, asked]).toEqual([true, "holiday xmas not found", 2]);
    } finally {
      await plain.$disconnect();
      await own.end();
    }
  });

  test("the ids a user holds a permission on, as text or as the key's type", async () => {
    expect(await actingAs("3", () => db.$authz.ids("project", "view"))).toEqual(["1", "3"]);
    expect(await actingAs("3", () => db.$authz.ids("project", "edit", Number))).toEqual([1]);
  });

  test("keys: a model's key fields, named where they aren't its id", async () => {
    const own = new pg.Pool({ connectionString: APP, max: 2 });
    const named = (keys: Record<string, string[]>) =>
      new PrismaClient({ adapter: signedIn(new PrismaPg(own)) }).$extends(authz({ keys }));
    const keyed = named({ Note: ["id"], Member: ["project_id", "user_id"] });
    const wrong = named({ Note: ["id", "project_id"] });                      // notes' key is one column
    try {
      await expect(actingAs("3", () => keyed.note.update({ where: { id: 1 }, data: { body: "x" } }))).rejects.toBeRefused("update", "note.edit");
      const member = await actingAs("2", () =>
        keyed.member.findUniqueOrThrow({ where: { project_id_user_id: { project_id: 9, user_id: 9 } } })).catch((e) => e);
      expect(member.message).toBe("app.members (9,9) not found");
      // keys the database can't take, or a where without them: nothing to ask, Prisma's own error stays
      const two = await actingAs("3", () => wrong.note.update({ where: { id: 1, project_id: 1 }, data: { body: "x" } })).catch((e) => e);
      const one = await actingAs("3", () => wrong.note.update({ where: { id: 1 }, data: { body: "x" } })).catch((e) => e);
      expect([two.code, one.code]).toEqual(["P2025", "P2025"]);
    } finally {
      await keyed.$disconnect();
      await wrong.$disconnect();
      await own.end();
    }
  });

  test("an extension given as a function, and the adapter's other methods", async () => {
    const own = new pg.Pool({ connectionString: APP, max: 2 });
    const factory = signedIn(new PrismaPg(own));
    const plain = new PrismaClient({ adapter: factory });
    // given this client, as Prisma gives it: what it adds goes through authz() too
    const viaFunction = plain.$extends(authz()).$extends((client) =>
      client.$extends({ client: { $mine: () => client.note.findMany({ orderBy: { id: "asc" } }) } }));
    try {
      expect((await actingAs("2", () => viaFunction.note.findMany())).map((n) => n.id)).toEqual([2, 3]);
      expect((await actingAs("2", () => viaFunction.$mine())).map((n) => n.id)).toEqual([2, 3]);
      await expect(actingAs("2", () => plain.note.findMany())).rejects.toThrow("isn't extended with authz()");
      expect([factory.provider, factory.connectToShadowDb.name]).toEqual(["postgres", "bound connectToShadowDb"]);
    } finally {
      await plain.$disconnect();
      await own.end();
    }
  });

  test("an adapter that ends its own transactions, and a sign-in or a rollback that fails", async () => {
    const own = new pg.Pool({ connectionString: APP, max: 2 });
    const inner = new PrismaPg(own);
    const ended: string[] = [];
    const fail = { signIn: false, rollback: false };
    type Query = { sql: string; args: unknown[]; argTypes: unknown[] };
    type Tx = { executeRaw(q: Query): Promise<number>; commit(): Promise<void>; rollback(): Promise<void> };
    // its commit() and rollback() send COMMIT and ROLLBACK themselves (usePhantomQuery), as some of Prisma's do
    const phantom = {
      provider: inner.provider,
      adapterName: inner.adapterName,
      connect: async () => {
        const adapter = await inner.connect();
        return Object.assign(Object.create(adapter), {
          startTransaction: async (level?: string) => {
            const tx = (await adapter.startTransaction(level as never)) as unknown as Tx;
            const send = (sql: string) => tx.executeRaw({ sql, args: [], argTypes: [] });
            return Object.assign(Object.create(tx), {
              options: { usePhantomQuery: true },
              executeRaw: async (q: Query) => {
                if (/^(COMMIT|ROLLBACK)$/.test(q.sql)) ended.push(`sent ${q.sql}`);
                if (fail.signIn && q.sql.includes("authz.act_as")) throw new Error("the sign-in failed");
                return tx.executeRaw(q);
              },
              commit: async () => { ended.push("commit()"); await send("COMMIT"); await tx.commit(); },
              rollback: async () => {
                ended.push("rollback()");
                await send("ROLLBACK");
                await tx.rollback();
                if (fail.rollback) throw new Error("the rollback failed");      // (after giving the connection back)
              },
            });
          },
        });
      },
    };
    const client = new PrismaClient({ adapter: signedIn(phantom as unknown as PrismaPg) }).$extends(authz());
    const count = () => client.$queryRawUnsafe<{ n: number }[]>("SELECT count(*)::int AS n FROM app.projects");
    try {
      expect(await actingAs("2", count)).toEqual([{ n: 2 }]);
      expect(await actingAs("2", () => client.$transaction(async (tx) => tx.project.count()))).toBe(2);
      expect(ended).toEqual(["commit()", "commit()"]);                     // the adapter's own: none sent besides
      fail.rollback = true;
      await expect(actingAs("2", () => client.$queryRawUnsafe("SELECT * FROM public._prisma_migrations")))
        .rejects.toThrow("permission denied");                             // the statement's error, not the rollback's
      fail.signIn = true;
      await expect(actingAs("2", count)).rejects.toThrow("the sign-in failed");
      await expect(actingAs("2", () => client.$transaction(async (tx) => tx.project.count()))).rejects.toThrow("the sign-in failed");
      expect(ended.slice(2)).toEqual(["rollback()", "rollback()", "rollback()"]);
    } finally {
      await client.$disconnect();
      await own.end();
    }
  });
});

describe("@rowstile/vitest", () => {
  test("what the matchers say when a check fails", () => {
    const refused = new Refused(REFUSED, "app.notes", "update", ["no   update : edit"]);
    expect(matchers.toBeRefused(refused).message()).toBe(`expected the write not to be refused, but: ${REFUSED}`);
    expect(matchers.toBeRefused(refused, "delete").message()).toBe(`expected the delete rule to refuse it, but the update rule did: ${REFUSED}`);
    expect(matchers.toBeRefused(refused, "update", "project.edit").message())
      .toBe(`expected "project.edit" in the reason, got:\n${REFUSED}\nno   update : edit`);
    expect(matchers.toBeRefused(refused, "update", "update : edit").pass).toBe(true);   // the reason's lines count
    expect(matchers.toBeRefused(new Error("boom")).message()).toBe("expected a refused write, got Error: boom");
    expect(matchers.toBeRefused({ rows: 1 }).message()).toBe('expected a refused write, got {"rows":1}');
    expect(matchers.toBeRefused(Symbol("nothing")).message()).toBe("expected a refused write, got Symbol(nothing)");
    expect(matchers.toBeNotFound(new NotFound("app.notes", "1")).message()).toBe("expected the row to be found, but: app.notes 1 not found");
    expect(matchers.toBeNotFound(refused).message()).toBe(`expected NotFound, got Refused: ${REFUSED}`);
    expect(asUser(3, () => current())).toEqual({ type: "user", id: "3" });
  });

  test("the worker's number, from Vitest's or Jest's variable", () => {
    vi.stubEnv("VITEST_POOL_ID", undefined);
    vi.stubEnv("VITEST_WORKER_ID", "7");
    try {
      expect(workerId()).toBe("7");
      vi.stubEnv("VITEST_WORKER_ID", undefined);
      vi.stubEnv("JEST_WORKER_ID", "4");
      expect(workerId()).toBe("4");
      vi.stubEnv("JEST_WORKER_ID", undefined);
      expect(workerId()).toBe("1");
    } finally {
      vi.unstubAllEnvs();
    }
  });

  test("a database per worker: kept, copied again, and why it can't be copied", async () => {
    const tests = process.env.ROWSTILE_TESTS_DSN!;
    vi.stubEnv("VITEST_POOL_ID", "8");
    try {
      const copy = await databasePerWorker(tests);
      expect([copy.url.endsWith("_w8"), copy.appUrl]).toEqual([true, undefined]);
      const owner = new pg.Client({ connectionString: copy.url });
      await owner.connect();
      await owner.query("INSERT INTO app.users VALUES (1, 'ann')");
      await owner.end();
      const users = async () => {
        const c = new pg.Client({ connectionString: copy.url });
        await c.connect();
        try {
          return (await c.query("SELECT count(*)::int AS n FROM app.users")).rows[0].n;
        } finally {
          await c.end();
        }
      };
      expect((await databasePerWorker(tests, { fresh: false })).url).toBe(copy.url);
      expect(await users()).toBe(1);                                         // kept, with what was written
      await databasePerWorker(tests);
      expect(await users()).toBe(0);                                         // copied again: as migrated
      const holding = new pg.Client({ connectionString: tests });            // something connected to the original
      await holding.connect();
      try {
        await expect(databasePerWorker(tests)).rejects.toThrow("can't be copied while anything is connected to it");
      } finally {
        await holding.end();
      }
      // the database's own errors: a role that may not create databases, an original that isn't there
      const asApp = new URL(APP);
      asApp.pathname = new URL(tests).pathname;
      await expect(databasePerWorker(asApp.toString())).rejects.toMatchObject({ code: "42501" });
      const gone = new URL(tests);
      gone.pathname += "_gone";
      await expect(databasePerWorker(gone.toString())).rejects.toMatchObject({ code: "3D000" });
    } finally {
      vi.unstubAllEnvs();
    }
  });
});

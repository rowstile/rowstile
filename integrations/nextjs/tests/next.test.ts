// @rowstile/next in this process, each way it can go: the servers test.sh starts run it too (conformance.test.ts),
// but what runs there isn't measured. Next's connection() is the test's own here: it answers as Next does inside a
// request, inside a cache, outside a request and inside after().
import pg from "pg";
import { afterAll, beforeEach, describe, expect, test, vi } from "vitest";
import { actingAs, errorCode, NotFound, NotSignedIn, principal, Refused, sqlstate } from "@rowstile/client";
import { authz as rowstile } from "@rowstile/pg";
import { action, authzRoutes, checkAtStart, keepOutOfCaches, route } from "@rowstile/next";
import { db, pool } from "@/db";
import { APP, OWNER, seed } from "./data";

const { connection } = vi.hoisted(() => ({ connection: vi.fn(async (): Promise<void> => undefined) }));
vi.mock("next/server.js", () => ({ connection }));

beforeEach(async () => {
  connection.mockReset();
  connection.mockResolvedValue(undefined);
  await seed();
});
afterAll(async () => {
  await pool.end();
  await db.$disconnect();
});

const IN_CACHE = 'Route /notes used `connection()` inside "use cache". Accessing Dynamic data sources inside a cache scope is not supported.';

describe("signed-in reads are kept out of caches", () => {
  test("Next is asked for a dynamic render before a sign-in; nobody's reads may be cached", async () => {
    await keepOutOfCaches(principal(null));
    expect(connection).not.toHaveBeenCalled();
    await keepOutOfCaches(principal(1));                                      // inside a request: a dynamic render
    expect(connection).toHaveBeenCalledTimes(1);
    connection.mockRejectedValueOnce(new Error("`connection` was called outside a request scope."));
    await keepOutOfCaches(principal(1));                                      // a script, a worker: no render
    connection.mockRejectedValueOnce(new Error("Route /x used `connection()` inside `after()`."));
    await keepOutOfCaches(principal(1));                                      // after the response: no render
    connection.mockRejectedValueOnce(new Error(IN_CACHE));
    await expect(keepOutOfCaches(principal(1))).rejects.toThrow('inside "use cache"');
    connection.mockRejectedValueOnce("not an Error");
    await expect(keepOutOfCaches(principal(1))).rejects.toBe("not an Error");
  });

  test("inside a cache, a transaction signed in as someone fails instead of reading", async () => {
    const p = new pg.Pool({ connectionString: APP });
    try {
      connection.mockRejectedValue(new Error(IN_CACHE));
      const read = (who: string | null) => actingAs(who, () => rowstile(p).query("SELECT id FROM app.projects ORDER BY id"));
      await expect(read("1")).rejects.toThrow('inside "use cache"');
      expect((await read(null)).rows.map((r) => r.id)).toEqual([3]);       // the same for everyone: it may be cached
    } finally {
      await p.end();
    }
  });
});

test("checkAtStart: the server stops on a connection that skips row-level security, with why", async () => {
  const exit = vi.spyOn(process, "exit").mockImplementation((() => undefined) as never);
  const said = vi.spyOn(console, "error").mockImplementation(() => undefined);
  const owner = new pg.Pool({ connectionString: OWNER });
  try {
    await checkAtStart(rowstile(owner));
    expect(exit).toHaveBeenCalledWith(1);
    expect(said.mock.calls[0][0]).toMatch(/^rowstile: the app's database connection can't be used with rowstile: .*an owner skips row-level security/);
    await checkAtStart({ check: async () => { throw "the database is down"; } });   // not an Error: said as it is
    expect(said.mock.calls[1][0]).toBe("rowstile: the database is down");
    exit.mockClear();
    await checkAtStart(db.$authz);                                           // the app's role: it starts
    expect(exit).not.toHaveBeenCalled();
  } finally {
    exit.mockRestore();
    said.mockRestore();
    await owner.end();
  }
});

describe("route handlers and server actions", () => {
  const rename = async (id: number) => {
    await db.note.update({ where: { id }, data: { body: "renamed" } });
    return id;
  };
  const notSignedIn = Object.assign(new Error("nobody signed in in this transaction"), { code: "28000" });

  test("route: a refusal is 403 with the reason, a hidden row 404; other errors are thrown", async () => {
    const PATCH = route(async (req: Request) => Response.json({ id: await rename(Number(new URL(req.url).searchParams.get("id"))) }));
    const patch = (who: string, id: number) => actingAs(who, () => PATCH(new Request(`http://app.test/notes?id=${id}`, { method: "PATCH" })));
    const refused = await patch("3", 1);
    expect([refused.status, refused.headers.get("content-type")]).toEqual([403, "application/problem+json"]);
    expect(await refused.json()).toMatchObject({ detail: "permission denied: user 3 may not update row 1 of app.notes", command: "update" });
    expect((await patch("2", 1)).status).toBe(404);
    expect((await patch("3", 4)).status).toBe(200);
    await expect(route(async () => { throw new Error("the app's"); })()).rejects.toThrow("the app's");
    await expect(route(async () => { throw notSignedIn; })()).rejects.toBeInstanceOf(NotSignedIn);
  });

  test("action: { ok, value } or the problem; other errors are thrown", async () => {
    const act = action(rename);
    expect(await actingAs("3", () => act(4))).toEqual({ ok: true, value: 4 });
    const refused = await actingAs("3", () => act(1));
    expect(!refused.ok && [refused.problem.status, refused.problem.command]).toEqual([403, "update"]);
    const hidden = await actingAs("2", () => act(1));
    expect(!hidden.ok && hidden.problem.status).toBe(404);
    await expect(action(async () => { throw new Error("the app's"); })()).rejects.toThrow("the app's");
    await expect(action(async () => { throw notSignedIn; })()).rejects.toBeInstanceOf(NotSignedIn);
  });

  // 16: a call the database turns down that is no refusal answers as its code's page says, with the database's
  // words: what it names isn't there (AZ708) 404, a missing or wrong argument (AZ710) 400, a call that needs someone
  // signed in (AZ714) or a login refused (AZ703) 401, a move inside itself (AZ713) 409. Each is [who, the call].
  const one = new pg.Pool({ connectionString: APP, max: 1 });
  afterAll(() => one.end());
  const calls = {
    nobody: ["1", () => db.$authz.share("project", 1, "viewer", "user", 99)],   // a share with someone who doesn't exist
    noKey: ["1", () => db.$queryRaw`SELECT 1 AS ok FROM authz.revoke_api_key(${987654}::bigint)`],   // an API key of ann's
    negative: ["1", () => db.$authz.list("project", "view", { limit: -1 })],
    signInFirst: [null, () => db.$authz.requestAccess("project", 1, "viewer", "the review")],
    // through pg: Prisma's driver adapter keeps no hint, so no code, for a 28000
    loginRefused: ["1", () => rowstile(one).query("SELECT authz.login_key('ak_nope')")],
    inside: ["1", () => db.folder.update({ where: { id: 1 }, data: { parent_id: 2 } })],
  } satisfies Record<string, [string | null, () => Promise<unknown>]>;
  const problem = (kind: string, title: string, status: number, detail: string, code: string) =>
    ({ type: `https://rowstile.dev/problems/${kind}`, title, status, detail, code });
  const expected: Record<keyof typeof calls, ReturnType<typeof problem>> = {
    nobody: problem("not-found", "Not Found", 404, "there is no user 99", "AZ708"),
    noKey: problem("not-found", "Not Found", 404, "no API key 987654 of yours", "AZ708"),
    negative: problem("bad-argument", "Bad Request", 400, "the page size must not be negative (got -1)", "AZ710"),
    signInFirst: problem("not-signed-in", "Unauthorized", 401, "sign in first", "AZ714"),
    loginRefused: problem("not-signed-in", "Unauthorized", 401, "invalid API key", "AZ703"),
    inside: problem("conflict", "Conflict", 409, "folder 1 cannot be moved inside itself", "AZ713"),
  };

  test("16: route: each code as its page says, with the database's words", async () => {
    for (const [name, [who, call]] of Object.entries(calls)) {
      const r = await actingAs(who, () => route(async () => { await call(); return new Response(null, { status: 204 }); })());
      const want = expected[name as keyof typeof calls];
      expect([r.status, r.headers.get("content-type"), await r.json()], name).toEqual([want.status, "application/problem+json", want]);
    }
  });

  test("16: action: each comes back as its problem", async () => {
    for (const [name, [who, call]] of Object.entries(calls)) {
      expect(await actingAs(who, () => action(call)()), name).toEqual({ ok: false, problem: expected[name as keyof typeof calls] });
    }
  });

  // 16: a refusal by the database's own code is 403 (AZ705: the shares of a project bo may not share; AZ704: a key
  // made in a session signed in with a key that may only read; AZ715: a key a service makes for itself); the app's
  // mistakes stay errors: a share the policy doesn't declare (AZ706), a name not in the policy (AZ707), who is
  // signed in changed by hand (AZ702, not NotSignedIn). Through route() and action() alike
  test("16: a refusal by the database's code is 403; the app's mistakes are thrown: route and action", async () => {
    const refused = (detail: string, code: string) => ({ type: "https://rowstile.dev/problems/refused", title: "Forbidden",
      status: 403, detail, table: null, command: null, why: [], code });
    const owner = new pg.Client({ connectionString: OWNER });      // a key of ann's that may only read
    await owner.connect();
    let key: string;
    try {
      await owner.query("BEGIN");
      await owner.query("SELECT authz.act_as('user', '1')");
      key = (await owner.query("SELECT authz.create_api_key('ro', 'read') AS k")).rows[0].k;
      await owner.query("COMMIT");
    } finally {
      await owner.end();
    }
    const refusals: Record<string, [string, () => Promise<unknown>, ReturnType<typeof refused>]> = {
      shares: ["2", () => db.$authz.listShares("project", 1), refused("you cannot see the shares of project 1", "AZ705")],
      scoped: ["1", () => rowstile(one).transaction(async (c) => {
        await c.query("SELECT authz.login_key($1)", [key]);
        return c.query("SELECT authz.create_api_key('more')");
      }), refused("this session is read-only (viewing as someone else, or a read-only token)", "AZ704")],
      // a call that is for users, made by a service (rowstile help AZ715): a refusal too
      service: ["1", () => rowstile(one).transaction(async (c) => {
        await c.query("SELECT authz.act_as('service', '1')");
        return c.query("SELECT authz.create_api_key('mine')");
      }), refused("authz.create_api_key for oneself is for users, not services (service 1 is signed in)", "AZ715")],
    };
    for (const [name, [who, call, want]] of Object.entries(refusals)) {
      const r = await actingAs(who, () => route(async () => { await call(); return new Response(null, { status: 204 }); })());
      expect([r.status, r.headers.get("content-type"), await r.json()], `route: ${name}`).toEqual([403, "application/problem+json", want]);
      expect(await actingAs(who, () => action(call)()), `action: ${name}`).toEqual({ ok: false, problem: want });
    }
    const mistakes: [string, () => Promise<unknown>, unknown[]][] = [
      ["1", () => db.$authz.share("project", 1, "member" as never, "user", 2),
        [false, "AZ706", "P0001", expect.stringContaining("the policy does not allow sharing project.member with user")]],
      ["1", () => db.$authz.list("nosuch" as never, "view" as never),
        [false, "AZ707", "P0001", expect.stringContaining("no permission nosuch.view in the policy")]],
      ["1", () => rowstile(one).transaction(async (c) => {
        await c.query("SELECT set_config('authz.user_id', '2', true)");
        return c.query("SELECT count(*) FROM app.notes");
      }), [false, "AZ702", "28000", "who is signed in was changed after signing in"]],
    ];
    const thrown = (e: unknown) => [e instanceof NotSignedIn, errorCode(e), sqlstate(e), (e as Error).message];
    for (const [who, call, want] of mistakes) {
      const byRoute = await actingAs(who, () => route(async () => { await call(); return new Response(null, { status: 204 }); })())
        .catch((e: unknown) => e);
      expect(thrown(byRoute), "route").toEqual(want);
      expect(thrown(await actingAs(who, () => action(call)()).catch((e: unknown) => e)), "action").toEqual(want);
    }
  });
});

describe("authzRoutes, for @rowstile/react", () => {
  const { GET, POST } = authzRoutes({ calls: db.$authz });
  const get = (who: string, path: string) => actingAs(who, () => GET(new Request(`http://app.test/api/authz/${path}`)));
  // (bytes, for a request with no content type at all: a string body is text/plain)
  const post = (who: string | null, path: string, body: object, type: string | null = "application/json") =>
    actingAs(who, () => POST(new Request(`http://app.test/api/authz/${path}`, {
      method: "POST", body: new TextEncoder().encode(JSON.stringify(body)), headers: type ? { "content-type": type } : {},
    })));

  test("GET: a list's permissions, the shares, and nothing else", async () => {
    expect(await (await get("3", "perms?type=project&ids=1&ids=3")).json()).toEqual({ "1": ["edit", "view"], "3": ["view"] });
    expect(await (await get("3", "perms")).json()).toEqual({});                       // no type, no ids
    expect(await (await get("1", "shares?type=project&id=1")).json()).toEqual([]);
    const noId = await get("1", "shares?type=project");
    expect([noId.status, (await noId.json()).code]).toEqual([403, "AZ705"]);      // a share of no object: none to see
    const unknown = await get("1", "nothing");
    expect([unknown.status, await unknown.json()]).toEqual([404, { title: "Not Found", status: 404 }]);
    expect((await actingAs("1", () => GET(new Request("http://app.test/")))).status).toBe(404);   // no route's name at all
    const events = await get("1", "events");                                    // no change feed given
    expect([events.status, (await events.json()).detail]).toEqual([404, "no change feed: authzRoutes({ changes })"]);
  });

  test("POST: JSON only; a long list, a share and its end, an access request", async () => {
    const form = await post("1", "share", { type: "project", id: "1" }, "application/x-www-form-urlencoded");
    expect(form.status).toBe(415);
    expect((await post("1", "share", { type: "project", id: "1" }, null)).status).toBe(415);   // no type at all
    expect(await (await post("3", "perms", { type: "project", ids: [1, 3] })).json()).toEqual({ "1": ["edit", "view"], "3": ["view"] });
    expect(await (await post("3", "perms", { type: "project", ids: "1" })).json()).toEqual({});   // not a list
    const share = { type: "project", id: "1", relation: "viewer", subjectType: "user", subjectId: "2" };
    expect(await (await post("1", "share", share)).json()).toEqual({ ok: true });
    expect((await (await get("1", "shares?type=project&id=1")).json()).map((s: { subject_id: string }) => s.subject_id)).toEqual(["2"]);
    expect(await (await post("1", "unshare", share)).json()).toEqual({ ok: true });
    const asked = await (await post("3", "request", { type: "project", id: "2", relation: "viewer", reason: "the review" })).json();
    expect(asked.id).toMatch(/^\d+$/);
    // a request without a reason: the database says what is missing (AZ710), which is the user's to fix: 400
    const why = await post("2", "request", { type: "project", id: "1", relation: "viewer" });
    expect([why.status, why.headers.get("content-type"), await why.json()]).toEqual([400, "application/problem+json", {
      type: "https://rowstile.dev/problems/bad-argument", title: "Bad Request", status: 400, detail: "say why you need it",
      code: "AZ710",
    }]);
    // 16: from someone not signed in: 401, in the database's words (rowstile help AZ714)
    const anonymous = await post(null, "request", { type: "project", id: "1", relation: "viewer", reason: "the review" });
    expect([anonymous.status, await anonymous.json()]).toEqual([401, {
      type: "https://rowstile.dev/problems/not-signed-in", title: "Unauthorized", status: 401, detail: "sign in first",
      code: "AZ714",
    }]);
    // 16: a share with someone who isn't there: 404, in the database's words
    const nobody = await post("1", "share", { ...share, subjectId: "99" });
    expect([nobody.status, await nobody.json()]).toEqual([404, {
      type: "https://rowstile.dev/problems/not-found", title: "Not Found", status: 404, detail: "there is no user 99",
      code: "AZ708",
    }]);
    // a share the policy doesn't declare (AZ706) is the app's mistake, not the user's: it stays an error; so does a
    // type not in the policy (AZ707)
    await expect(post("1", "share", { ...share, relation: "member" })).rejects.toThrow("does not allow sharing project.member");
    const noType = await post("1", "perms", { type: "nosuch", ids: [1] }).catch((e: unknown) => e);
    expect([noType instanceof Response, errorCode(noType)]).toEqual([false, "AZ707"]);
    expect((await post("1", "nothing", {})).status).toBe(404);
  });

  test("events: told of each change, pinged, and listening ends once when the page goes", async () => {
    vi.useFakeTimers();
    let listening = 0;
    let notify = () => {};
    const { GET: events } = authzRoutes({
      calls: db.$authz,
      changes: (onChange) => { listening += 1; notify = onChange; return () => { listening -= 1; }; },
    });
    try {
      const page = new AbortController();
      const response = await events(new Request("http://app.test/api/authz/events", { signal: page.signal }));
      expect(listening).toBe(1);                                                 // (as many as 1000 by default)
      const reader = response.body!.getReader();
      const text = async () => new TextDecoder().decode((await reader.read()).value);
      expect(await text()).toBe(": connected\n\n");
      notify();
      expect(await text()).toBe("event: changed\ndata: {}\n\n");
      vi.advanceTimersByTime(25_000);
      expect(await text()).toBe(": ping\n\n");
      await reader.cancel();                                                     // the page went: the stream is cancelled,
      expect(listening).toBe(0);
      page.abort();                                                              // and the request aborted
      notify();                                                                  // a feed that tells all the same
      vi.advanceTimersByTime(25_000);
      expect(listening).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});

test("NotFound and Refused from a route keep what Prisma raised", async () => {
  const hidden = await actingAs("2", () => db.note.update({ where: { id: 1 }, data: { body: "x" } })).catch((e) => e);
  expect([hidden instanceof NotFound, (hidden as { cause?: { code?: string } }).cause?.code]).toEqual([true, "P2025"]);
  const refused = await actingAs("3", () => db.note.update({ where: { id: 1 }, data: { body: "x" } })).catch((e) => e);
  expect([refused instanceof Refused, (refused as { cause?: { code?: string } }).cause?.code]).toEqual([true, "P2025"]);
});

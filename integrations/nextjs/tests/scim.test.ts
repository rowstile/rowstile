// An identity provider's SCIM requests through the app's route (app/scim/v2/[...scim]/route.ts), as Microsoft Entra
// ID and Okta send them. The database answers each one (authz.scim; core's tests/scim.sh checks what it answers):
// these check what the route passes on and what it sends back. Each check runs twice: through the server test.sh
// started, as a provider reaches it, and on the same handlers called here, where what runs of the SDK is measured.
// The provider is user 9, whose API key is the bearer token; its groups are the projects' members, and the app's
// function (app.scim_user, a migration of the app's) makes its users.
import { readFileSync, statSync } from "node:fs";
import pg from "pg";
import postgres from "postgres";
import { drizzle } from "drizzle-orm/node-postgres";
import { drizzle as drizzlePostgres } from "drizzle-orm/postgres-js";
import { afterAll, afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { actingAs, errorCode } from "@rowstile/client";
import { withAuthz } from "@rowstile/drizzle";
import { scimRoutes } from "@rowstile/next";
import { authz as rowstile } from "@rowstile/pg";
import { authz as postgresAuthz } from "@rowstile/postgres";
import { db, pool } from "@/db";
import { APP, OWNER, SERVER, SERVER_LOG, SERVER_ONE, as, seed } from "./data";

// What the tables' owner says once, in psql or a migration (docs/stacks/nextjs.md shows these lines): the provider
// is user 9, a user the app keeps for it; its groups are the projects' members; and what the endpoint reads of a user
const SET_UP = `
SELECT authz.set_scim('{
  "principal": "user:9",
  "group": "project.member", "group_name": "name",
  "user_name": "name", "user_active": "active", "user_resource": "scim",
  "user_function": "app.scim_user"
}');
`;
// ... and the provider's key, made once as that user
const MAKE_KEY = `
BEGIN;
SELECT authz.act_as('user', '9');
SELECT authz.create_api_key('the identity provider');   -- shown this once: the provider's bearer token
COMMIT;
`;
const ERROR = "urn:ietf:params:scim:api:messages:2.0:Error";
const PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const USER = "urn:ietf:params:scim:schemas:core:2.0:User";
const NOT_THE_PROVIDER = {
  schemas: [ERROR], status: "401",
  detail: "the bearer token is not an API key of the principal the SCIM settings name (rowstile help AZ721)",
};
const NO_JSON = {
  schemas: [ERROR], status: "400", scimType: "invalidSyntax",
  detail: "the request's body is no JSON, or is nested too deep to read (rowstile help AZ721)",
};
// the route's own two answers: what can't be passed on at all, and an error, which is the app's to see
const NO_TEXT = {
  schemas: [ERROR], status: "400", scimType: "invalidSyntax",
  detail: "the request is no text: bytes that are no UTF-8, or a NUL",
};
const FAILED = { schemas: [ERROR], status: "500", detail: "the request failed: the app's log says why" };
// one PATCH that adds a member and removes another: bo joins the group, cy leaves it
const BO_FOR_CY = {
  schemas: [PATCH],
  Operations: [
    { op: "add", path: "members", value: [{ value: "2" }] },
    { op: "remove", path: 'members[value eq "3"]' },
  ],
};
// a user as Okta writes one in a create: a password comes as a placeholder in each
const DEE = {
  schemas: [USER], userName: "dee", name: { givenName: "Dee", familyName: "User" },
  emails: [{ primary: true, value: "dee@example.com", type: "work" }], displayName: "Dee User", password: "1mz050nq",
  active: true,
};

const owner = new pg.Pool({ connectionString: OWNER, max: 1 });
/** A new API key of a user's own. */
async function keyOf(user: number, name: string): Promise<string> {
  const c = await owner.connect();
  try {
    await c.query("BEGIN");
    await c.query("SELECT authz.act_as('user', $1)", [String(user)]);
    const made = (await c.query("SELECT authz.create_api_key($1) AS k", [name])).rows[0].k as string;
    await c.query("COMMIT");
    return made;
  } finally {
    c.release();
  }
}
/** Project 1's members, as the table has them. */
const members = async () =>
  (await owner.query("SELECT user_id FROM app.members WHERE project_id = 1 ORDER BY 1")).rows.map((r) => r.user_id as number);

// While a test runs, the settings name user 9 as the provider, and `key` is its API key; after it the endpoint is
// off again (the rows are every test's own: seed)
let key = "";
beforeEach(async () => {
  await seed();
  await owner.query("INSERT INTO app.users VALUES (9, 'provisioning')");
  const made = (await owner.query(MAKE_KEY)) as unknown as pg.QueryResult[];    // (a result for each statement)
  key = made[2].rows[0].create_api_key as string;
  await owner.query("SELECT setval('app.provisioned_user_ids', 100)");
  await owner.query(SET_UP);
});
afterEach(() => owner.query("SELECT authz.set_scim('{}')"));
afterAll(async () => {
  await owner.end();
  await pool.end();
  await db.$disconnect();
});

interface Sent { body?: string | Uint8Array<ArrayBuffer>; headers?: Record<string, string> }
type Ask = (method: string, path: string, sent?: Sent) => Promise<Response>;
type Handlers = Record<string, (req: Request, context: { params: Promise<Record<string, string | string[]>> }) => Promise<Response>>;
const bearer = (k: string) => ({ authorization: `Bearer ${k}` });
const json = (body: unknown, headers: Record<string, string> = {}): Sent =>
  ({ body: JSON.stringify(body), headers: { "content-type": "application/scim+json", ...headers } });
const answer = async (r: Response) => [r.status, r.headers.get("content-type"), await r.json()];

const THROUGH = "through the server";
const HERE = "http://app.test";
const through: Ask = (method, path, sent = {}) => fetch(`${SERVER}/scim/v2/${path}`, { method, ...sent });
/** The handlers called as Next.js calls them: the request, and what the route's catch-all segment took of its
 *  address. Someone signed in to the app is a header for the server (x-user), and whom the code acts for here. */
const here = (handlers: Handlers, mount = "/scim/v2", more: Record<string, string> = {}): Ask => (method, path, sent = {}) => {
  const call = () => handlers[method](new Request(`${HERE}${mount}/${path}`, { method, ...sent }),
    { params: Promise.resolve({ ...more, scim: path.split("?")[0].split("/") }) });
  const user = sent.headers?.["x-user"];
  return user === undefined ? call() : actingAs(user, call);
};
const routes: Handlers = scimRoutes({ calls: db.$authz });

/** What was logged while fn ran: by the server (its log from there on), or here (console.error's words, and what
 *  it was given with them). */
async function logged(via: string, fn: () => Promise<void>): Promise<{ words: string; given: unknown[] }> {
  const start = statSync(SERVER_LOG).size;
  const said = vi.spyOn(console, "error").mockImplementation(() => undefined);
  try {
    await fn();
    if (via === THROUGH) return { words: readFileSync(SERVER_LOG).subarray(start).toString("utf8"), given: [] };
    return { words: said.mock.calls.map((c) => String(c[0])).join("\n"), given: said.mock.calls.map((c) => c[1]) };
  } finally {
    said.mockRestore();
  }
}

describe.each([[THROUGH, SERVER, through], ["on the handlers here", HERE, here(routes)]] as const)("%s", (via, base, ask) => {
  test("only the provider's key is answered", async () => {
    const anns = await keyOf(1, "ann's own");                   // a key, but not the provider's
    const refused = [
      await ask("GET", "Groups/1"),
      await ask("GET", "Groups/1", { headers: { "x-user": "1" } }),             // signed in to the app: no provider
      await ask("GET", "Groups/1", { headers: { "x-user": "9" } }),
      await ask("GET", "Groups/1", { headers: bearer("ak_00000000000000000000000000000000") }),
      await ask("GET", "Groups/1", { headers: bearer(anns) }),
      await ask("GET", "Groups/1", { headers: { authorization: `Basic ${key}` } }),
      await ask("GET", "Groups/1", { headers: { authorization: "Bearer" } }),
      await ask("PATCH", "Groups/1", json(BO_FOR_CY, bearer(anns))),
    ];
    for (const r of refused) {
      expect([r.headers.get("www-authenticate"), ...await answer(r)]).toEqual(["Bearer", 401, "application/scim+json", NOT_THE_PROVIDER]);
    }
    expect(await members()).toEqual([3]);
    // ... and what else a request says signs nobody in: the provider, though the app's session says ann
    for (const headers of [{ authorization: `bearer ${key}` }, { ...bearer(key), "x-user": "1" }]) {
      const answered = await ask("GET", "Groups/1", { headers });
      expect([answered.status, answered.headers.get("www-authenticate"), (await answered.json()).displayName]).toEqual([200, null, "Plans"]);
    }
  });

  test("what a provider asks before it starts", async () => {
    const get = (path: string) => ask("GET", path, { headers: bearer(key) });
    const config = await answer(await get("ServiceProviderConfig"));
    const schemas = await answer(await get("Schemas"));
    const types = await answer(await get("ResourceTypes"));
    // the query string goes to the database as it was sent: Entra ID's filter on a group's name, Okta's on a
    // user's, a space as %20 or as a plus sign
    const plans = await answer(await get("Groups?excludedAttributes=members&filter=displayName%20eq%20%22Plans%22"));
    const bo = await answer(await get("Users?filter=userName+eq+%22bo%22&startIndex=1&count=100"));
    const nobody = await answer(await get("Users?filter=userName%20eq%20%22nobody%22"));
    for (const [status, type] of [config, schemas, types, plans, bo, nobody]) {
      expect([status, type]).toEqual([200, "application/scim+json"]);
    }
    expect([config[2].patch, config[2].bulk.supported]).toEqual([{ supported: true }, false]);
    expect(schemas[2].Resources.map((s: { id: string }) => s.id)).toContain(USER);
    expect(types[2].Resources.map((t: { endpoint: string }) => t.endpoint).sort()).toEqual(["/Groups", "/Users"]);
    expect(plans[2].Resources.map((g: Record<string, unknown>) => [g.id, g.displayName, "members" in g])).toEqual([["1", "Plans", false]]);
    expect(bo[2].Resources.map((u: Record<string, unknown>) => [u.id, u.userName])).toEqual([["2", "bo"]]);
    expect([nobody[2].totalResults, nobody[2].Resources]).toEqual([0, []]);
    const bad = await answer(await get("Users?filter=userName%20co%20%22b%22"));
    expect([bad[0], bad[1], bad[2].scimType]).toEqual([400, "application/scim+json", "invalidFilter"]);
    const nowhere = await answer(await get("Nothing"));
    expect([nowhere[0], nowhere[1], nowhere[2].schemas, nowhere[2].status]).toEqual([404, "application/scim+json", [ERROR], "404"]);
  });

  test("a PATCH changes the members and the policy follows", async () => {
    // note 1 is the project's, so a member reads it: what the app's own route lists for bo and for cy
    const reads = async () =>
      Promise.all(["2", "3"].map(async (u) => ((await (await fetch(`${SERVER}/api/notes`, as(u))).json()) as number[]).includes(1)));
    expect(await reads()).toEqual([false, true]);
    const patched = await ask("PATCH", "Groups/1", json(BO_FOR_CY, bearer(key)));
    // Entra ID and Okta both take 204 for a group's PATCH: no body, and so no type for one
    expect([patched.status, await patched.text(), patched.headers.get("content-type"), patched.headers.get("location")])
      .toEqual([204, "", null, null]);
    expect(await members()).toEqual([2]);
    // bo reads the project's notes now, and cy, a member no longer, does not
    expect(await reads()).toEqual([true, false]);
    const group = await (await ask("GET", "Groups/1", { headers: bearer(key) })).json();
    expect([group.members, group.displayName]).toEqual([[{ value: "2" }], "Plans"]);
    // as authz.sync_members writes it, in one line of the audit trail, which says the provider did it
    const line = (await owner.query("SELECT user_id, object_type, object_id, relation, detail->>'added' AS added, " +
      "detail->>'removed' AS removed, detail->'members' AS members FROM authz.audit WHERE action = 'sync_members' " +
      "ORDER BY id DESC LIMIT 1")).rows[0];
    expect(line).toEqual({ user_id: "9", object_type: "project", object_id: "1", relation: "member", added: "1", removed: "1", members: ["2"] });
  });

  test("a user made is answered with where it is", async () => {
    const made = await ask("POST", "Users", json(DEE, bearer(key)));
    // 201, the user, and where it is: the route's own address, then what the database said
    const where = made.headers.get("location") ?? "";
    expect([where, ...await answer(made)]).toEqual([`${base}/scim/v2/Users/101`, 201, "application/scim+json",
      expect.objectContaining({ id: "101", userName: "dee" })]);
    const read = await ask("GET", where.slice(`${base}/scim/v2/`.length), { headers: bearer(key) });
    const user = await read.json();
    expect([read.status, user.id, "password" in user]).toEqual([200, "101", false]);
    const again = await ask("POST", "Users", json(DEE, bearer(key)));
    expect([again.headers.get("location"), again.status, (await again.json()).scimType]).toEqual([null, 409, "uniqueness"]);
    // Entra ID changes one attribute (op Replace, a path)
    const renamed = await ask("PATCH", "Users/101", json(
      { schemas: [PATCH], Operations: [{ op: "Replace", path: "userName", value: "dee.user" }] }, bearer(key)));
    expect([renamed.status, (await renamed.json()).userName]).toEqual([200, "dee.user"]);
    expect((await owner.query("SELECT name FROM app.users WHERE id = 101")).rows).toEqual([{ name: "dee.user" }]);
    // behind a proxy, the address the provider asked: the first host and scheme the proxies handed on
    const eli = await ask("POST", "Users", json({ ...DEE, userName: "eli" },
      { ...bearer(key), "x-forwarded-host": "idp.example, proxy.internal", "x-forwarded-proto": "https, http" }));
    expect([eli.status, eli.headers.get("location")]).toEqual([201, "https://idp.example/scim/v2/Users/102"]);
    const deleted = await ask("DELETE", "Users/101", { headers: bearer(key) });
    expect([deleted.status, await deleted.text(), deleted.headers.get("content-type")]).toEqual([204, "", null]);
    const gone = await ask("GET", "Users/101", { headers: bearer(key) });
    expect([gone.status, (await gone.json()).schemas]).toEqual([404, [ERROR]]);
  });

  test("the app's function keeps what the provider says nothing of", async () => {
    const row = async (id: number) => (await owner.query(
      "SELECT name, email, active, scim->>'displayName' AS shown, scim ? 'password' AS password FROM app.users WHERE id = $1", [id])).rows[0];
    expect((await ask("POST", "Users", json(DEE, bearer(key)))).status).toBe(201);
    expect(await row(101)).toEqual({ name: "dee", email: "dee@example.com", active: true, shown: "Dee User", password: false });
    // a GET answers the user as the provider wrote it, from the column the settings name (user_resource)
    const read = await (await ask("GET", "Users/101", { headers: bearer(key) })).json();
    expect([read.displayName, read.emails[0].value, read.active]).toEqual(["Dee User", "dee@example.com", true]);
    // Okta deactivates a user (op replace, no path, active false in the value): the row stays, not active
    const off = await ask("PATCH", "Users/101", json({ schemas: [PATCH], Operations: [{ op: "replace", value: { active: false } }] }, bearer(key)));
    expect([off.status, (await off.json()).active]).toEqual([200, false]);
    expect(await row(101)).toEqual({ name: "dee", email: "dee@example.com", active: false, shown: "Dee User", password: false });
    // a PUT that says less than the user had (no email, nothing of active): the app's function keeps both
    const less = await ask("PUT", "Users/101", json({ schemas: [USER], userName: "dee" }, bearer(key)));
    expect([less.status, (await less.json()).active]).toEqual([200, false]);
    expect(await row(101)).toEqual({ name: "dee", email: "dee@example.com", active: false, shown: null, password: false });
    // a user the app made itself, whom the provider never wrote: a PATCH starts from what the columns say
    const named = await ask("PATCH", "Users/2", json(
      { schemas: [PATCH], Operations: [{ op: "Replace", path: "displayName", value: "Bo B." }] }, bearer(key)));
    expect([named.status, (await named.json()).userName]).toEqual([200, "bo"]);
    expect(await row(2)).toEqual({ name: "bo", email: null, active: true, shown: "Bo B.", password: false });
  });

  test("a body goes on unread and nothing sent is an error", async () => {
    // The route passes the body on as it was sent, and the database says when it is no JSON, to the provider alone.
    // So what one JSON reader takes and another doesn't is no matter here: no such body fails, with or without the key
    const bodies = [
      '{"userName": ',
      "dee",
      '{"userName": "dee", "weight": NaN}',                    // JavaScript has the number; JSON has no NaN
      '{"userName": "dee\\u0000"}',                            // JSON, with a text no text of the database holds
      "[".repeat(100_000),                                     // nested deeper than the server reads
      "﻿" + JSON.stringify(DEE),                          // a byte order mark, as it was sent: no JSON to the database
    ];
    const said = await logged(via, async () => {
      for (const body of bodies) {
        expect(await answer(await ask("POST", "Users", { body, headers: bearer(key) })), body.slice(0, 40))
          .toEqual([400, "application/scim+json", NO_JSON]);
        // without the key the body is not read: the key is refused
        expect(await answer(await ask("POST", "Users", { body })), body.slice(0, 40)).toEqual([401, "application/scim+json", NOT_THE_PROVIDER]);
      }
      // what is no text can't be passed on at all: the route's own answer, whoever asks
      const noText = [
        await ask("POST", "Users", { body: new Uint8Array([0xff, 0xfe]), headers: bearer(key) }),
        await ask("POST", "Users", { body: '{"userName": "d\0e"}', headers: bearer(key) }),
        await ask("GET", "Users/%00", { headers: bearer(key) }),
        await ask("GET", "Users/%00"),
      ];
      for (const r of noText) expect(await answer(r)).toEqual([400, "application/scim+json", NO_TEXT]);
    });
    expect(said.words).not.toContain("authz.scim failed");
    const listed = await (await ask("GET", "Users?filter=userName%20eq%20%22dee%22", { headers: bearer(key) })).json();
    expect(listed.totalResults).toBe(0);
  });

  test("an error is 500 and the app's to see", async () => {
    // settings that no longer hold (the function they name is gone) are the app's mistake, not the provider's: the
    // database raises, the route answers 500 in SCIM's words and the app's log has the database's
    await owner.query("ALTER FUNCTION app.scim_user(text, jsonb) RENAME TO scim_user_gone");
    try {
      const said = await logged(via, async () => {
        expect(await answer(await ask("POST", "Users", json(DEE, bearer(key))))).toEqual([500, "application/scim+json", FAILED]);
        // a request that reads no such setting is answered
        expect((await ask("GET", "Users/2", { headers: bearer(key) })).status).toBe(200);
      });
      expect(said.words.split("\n").filter((line) => line.includes("authz.scim failed")))
        .toEqual([expect.stringMatching(/^rowstile: authz\.scim failed \(POST "Users"\)/)]);
      if (via === THROUGH) expect(said.words).toContain("scim_user");                  // the database's words, in the log
      else expect(said.given.map(errorCode)).toEqual(["AZ722"]);                      // rowstile help AZ722
    } finally {
      await owner.query("ALTER FUNCTION app.scim_user_gone(text, jsonb) RENAME TO scim_user");
    }
  });
});

describe("through the server alone", () => {
  // Next.js answers a HEAD with the GET handler, which passes the method on as it came: the database serves no HEAD
  // (405, to the provider alone). OPTIONS is Next.js's own answer
  test("HEAD is the database's to refuse, OPTIONS Next.js's to answer", async () => {
    const head = await fetch(`${SERVER}/scim/v2/Groups/1`, { method: "HEAD", headers: bearer(key) });
    expect([head.status, head.headers.get("content-type")]).toEqual([405, "application/scim+json"]);
    expect((await fetch(`${SERVER}/scim/v2/Groups/1`, { method: "HEAD" })).status).toBe(401);
    const options = await fetch(`${SERVER}/scim/v2/Groups/1`, { method: "OPTIONS" });
    expect([options.status, options.headers.get("allow")?.split(", ").sort()])
      .toEqual([204, ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]]);
  });

  // a request is asked in one transaction of its own: a pool of one connection answers it, and the next
  test("a pool of one connection is enough", async () => {
    const made = await fetch(`${SERVER_ONE}/scim/v2/Users`, { method: "POST", ...json(DEE, bearer(key)) });
    expect([made.status, made.headers.get("location")]).toEqual([201, `${SERVER_ONE}/scim/v2/Users/101`]);
    const read = await fetch(`${SERVER_ONE}/scim/v2/Users/101`, { headers: bearer(key) });
    expect([read.status, (await read.json()).userName]).toEqual([200, "dee"]);
  });
});

describe("on the handlers alone", () => {
  test("requests are not user requests: user() is never asked", async () => {
    // an app whose user() takes every request for a session's, and would say ann
    let asked = 0;
    const p = new pg.Pool({ connectionString: APP });
    const ask = here(scimRoutes({ calls: rowstile(p, { user: async () => { asked += 1; return "1"; } }) }));
    try {
      const group = await ask("GET", "Groups/1", { headers: bearer(key) });
      expect([group.status, (await group.json()).members]).toEqual([200, [{ value: "3" }]]);
      expect(await answer(await ask("GET", "Groups/1"))).toEqual([401, "application/scim+json", NOT_THE_PROVIDER]);
      expect((await ask("PATCH", "Groups/1", json(BO_FOR_CY, bearer(key)))).status).toBe(204);
      expect(await members()).toEqual([2]);
      expect(asked).toBe(0);
      expect((await rowstile(p, { user: async () => "1" }).query("SELECT id FROM app.notes ORDER BY id")).rows.map((r) => r.id))
        .toEqual([1, 3, 4]);                                    // (that user() says ann, to any other query)
    } finally {
      await p.end();
    }
  });

  test("the route's address is where its catch-all segment begins, wherever the app put it", async () => {
    // under a segment of the app's own (app/[tenant]/provisioning/[...scim]/route.ts)
    const under = here(routes, "/acme/provisioning", { tenant: "acme" });
    const made = await under("POST", "Users", json(DEE, bearer(key)));
    expect([made.status, made.headers.get("location")]).toEqual([201, `${HERE}/acme/provisioning/Users/101`]);
    // an address that ends with a slash (trailingSlash in next.config), and a key the address escapes
    const slash = await routes.GET(new Request(`${HERE}/scim/v2/Groups/1/`, { headers: bearer(key) }),
      { params: Promise.resolve({ scim: ["Groups", "1"] }) });
    expect([slash.status, (await slash.json()).displayName]).toEqual([200, "Plans"]);
    const escaped = await routes.GET(new Request(`${HERE}/scim/v2/Groups/%31`, { headers: bearer(key) }),
      { params: Promise.resolve({ scim: ["Groups", "1"] }) });
    expect([escaped.status, (await escaped.json()).id]).toEqual([200, "1"]);
    // a host a proxy handed on without a scheme: the request's own
    const eli = await routes.POST(new Request(`${HERE}/scim/v2/Users`,
      { method: "POST", ...json({ ...DEE, userName: "eli" }, { ...bearer(key), "x-forwarded-host": "idp.example" }) }),
      { params: Promise.resolve({ scim: ["Users"] }) });
    expect([eli.status, eli.headers.get("location")]).toEqual([201, "http://idp.example/scim/v2/Users/102"]);
    // a route that is no catch-all route passes no path on: the database knows no such address
    const bare = await routes.GET(new Request(`${HERE}/scim/v2`, { headers: bearer(key) }), { params: Promise.resolve({}) });
    expect([bare.status, (await bare.json()).schemas]).toEqual([404, [ERROR]]);
    // an escape that is no text (Next.js refuses such an address before any route)
    const noText = await routes.GET(new Request(`${HERE}/scim/v2/Users/%E0%A4%A`, { headers: bearer(key) }),
      { params: Promise.resolve({ scim: ["Users", "%E0%A4%A"] }) });
    expect(await answer(noText)).toEqual([400, "application/scim+json", NO_TEXT]);
  });

  // authz.scim over each driver: the same question, the same answer (a body that is none, a token that is none)
  test("the drivers' calls ask the database the same way", async () => {
    const p = new pg.Pool({ connectionString: APP });
    const sql = postgres(APP, { max: 2 });
    const drivers = { Prisma: db.$authz, pg: rowstile(p), "postgres.js": postgresAuthz(sql), "Drizzle on pg": withAuthz(drizzle(p)),
                      "Drizzle on postgres.js": withAuthz(drizzlePostgres(sql)) };
    try {
      let id = 100;
      for (const [name, a] of Object.entries(drivers)) {
        id += 1;
        // (acting for ann: the call signs nobody in all the same, and the key says who asks)
        const group = await actingAs("1", () => a.scim("GET", "Groups/1", "excludedAttributes=members", null, key));
        expect([group.status, JSON.parse(group.body ?? ""), group.location], name)
          .toEqual([200, expect.objectContaining({ id: "1", displayName: "Plans" }), null]);
        const made = await a.scim("POST", "Users", "", JSON.stringify({ ...DEE, userName: name }), key);
        expect([made.status, JSON.parse(made.body ?? "").userName, made.location], name).toEqual([201, name, `Users/${id}`]);
        expect(await a.scim("DELETE", `Users/${id}`, "", null, key), name).toEqual({ status: 204, body: null, location: null });
        const refused = await a.scim("GET", "Groups/1", "", null, null);
        expect([refused.status, JSON.parse(refused.body ?? ""), refused.location], name).toEqual([401, NOT_THE_PROVIDER, null]);
      }
    } finally {
      await p.end();
      await sql.end();
    }
  });
});

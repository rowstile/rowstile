// electricShape in the app's own process, with Electric's side stood in for where only that can say what was sent
// to it: nothing for someone not signed in, the URL and body a request becomes; and what the route refuses to be set
// up with. Who is signed in is the database's answer, as in the app.
import { afterAll, beforeAll, expect, test } from "vitest";
import { electricShape, syncPrincipal, type ElectricShape } from "@rowstile/client";
import { signedIn } from "../src/app.js";
import { pool } from "../src/db.js";
import { shapes } from "../src/shapes.gen.js";
import { as, owner, seed } from "./data.js";

beforeAll(() => seed());
afterAll(() => pool.end());

/** A stand-in for Electric: what it was asked, and its answer (no vary of its own). */
function recorder() {
  const asked: { url: URL; init: RequestInit }[] = [];
  const fetch = async (url: string | URL | Request, init: RequestInit = {}) => {
    asked.push({ url: new URL(String(url)), init });
    return new Response("[]", { status: 200, headers: { "content-type": "application/json" } });
  };
  return { asked, fetch: fetch as typeof globalThis.fetch };
}

const request = (query: string, init: RequestInit = {}) => new Request(`http://app/shapes/files?offset=-1${query}`, init);

test("E9: not signed in, nothing is asked of Electric", async () => {
  const electric = recorder();
  const files = electricShape(shapes["app.files"], { url: "http://electric/v1/shape", signedIn, vary: ["x-user"], fetch: electric.fetch });
  const r = await files(request(""));
  expect([r.status, r.headers.get("vary"), r.headers.get("cache-control")]).toEqual([401, "x-user", "no-store"]);
  expect(electric.asked).toEqual([]);
  // signed in: the shape the policy gives, whatever else the request said (no secret here: Electric runs without one)
  const ok = await files(request("&live=true&handle=h", { headers: as("2") }));
  expect([ok.status, ok.headers.get("vary")]).toEqual([200, "x-user"]);
  const url = electric.asked[0]!.url;
  expect(Object.fromEntries(url.searchParams)).toEqual({ offset: "-1", live: "true", handle: "h", table: "app.files",
    where: shapes["app.files"].where.user, "params[1]": "2" });
  // a POST's subset is sent on as the subset it is, as JSON
  await files(request("", { method: "POST", headers: as("2"), body: JSON.stringify({ where: "id = $1", params: { "1": "3" } }) }));
  expect([electric.asked[1]!.init.method, electric.asked[1]!.init.body]).toEqual(["POST", '{"where":"id = $1","params":{"1":"3"}}']);
});

test("E15: viewing as someone is a session limited too: refused", async () => {
  const viewing = await owner(async (c) => {
    await c.query("BEGIN");
    await c.query("SELECT authz.view_as('2', 'support ticket 7')");
    const p = await syncPrincipal(c);
    await c.query("ROLLBACK");
    return p;
  });
  expect(viewing).toEqual({ type: "user", id: "2", limited: true });
  const electric = recorder();
  const files = electricShape(shapes["app.files"], { url: "http://electric/v1/shape", signedIn: async () => viewing,
    vary: ["cookie"], fetch: electric.fetch });
  expect((await files(request(""))).status).toBe(403);
  // ... and a principal of a type the shape has no filter for gets none
  const bots = electricShape(shapes["app.files"], { url: "http://electric/v1/shape", vary: ["cookie"], fetch: electric.fetch,
    signedIn: async () => ({ type: "bot", id: "7", limited: false }) });
  const bot = await bots(request(""));
  expect([bot.status, ((await bot.json()) as { detail: string }).detail]).toEqual([403, "bot doesn't sync app.files"]);
  expect(electric.asked).toEqual([]);
});

test("what the route refuses to be set up with", () => {
  const notes: ElectricShape = shapes["app.notes"];
  const base = { url: "http://electric/v1/shape", signedIn, vary: ["cookie"] };
  expect(() => electricShape(notes, base)).toThrow("the policy masks body of app.notes: say which columns to sync");
  expect(() => electricShape(notes, { ...base, columns: ["id", "body"] })).toThrow("the policy masks app.notes.body, which is never synced");
  expect(() => electricShape(shapes["app.files"], { ...base, vary: [] })).toThrow("say which request headers tell users apart");
});

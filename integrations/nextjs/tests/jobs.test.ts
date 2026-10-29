// Work outside a request (preview): check 10 through a real queue (BullMQ on Redis, test.sh starts it), and Next's
// after(), work once the response is sent. Each signs in as whom it acts for, and nothing of it carries over: not
// to the worker's own code, not to the next request on the same connection.
import { readFileSync } from "node:fs";
import { Job, QueueEvents } from "bullmq";
import { afterAll, beforeEach, expect, test } from "vitest";
import { actingAs, current } from "@rowstile/client";
import { db, pool } from "@/db";
import { digests, digestWorker } from "@/queue";
import { EXPECTED, SERVER, SERVER_LOG, SERVER_ONE, as, seed } from "./data";

beforeEach(seed);
afterAll(async () => {
  await digests().close();
  await pool.end();
  await db.$disconnect();
});

const SERVICE = { count: 2, who: { type: "service", id: "1" } };   // service 1 reads project 1 and the public one
const until = async (ok: () => boolean | Promise<boolean>) => {
  for (let i = 0; i < 100 && !(await ok()); i++) await new Promise((r) => setTimeout(r, 100));
};

// 10: a background job signs in as a service principal, here queued by the server as the request's user
test("10: a job through a queue (BullMQ) acts for its service, whoever queued it", async () => {
  expect(process.env.REDIS_URL, "REDIS_URL (test.sh sets it)").toBeTruthy();
  const worker = digestWorker();
  const events = new QueueEvents("digest", { connection: { url: process.env.REDIS_URL } });
  const after: unknown[] = [];
  worker.on("completed", () => after.push(current() ?? "nobody"));   // the worker's own code, past the job
  try {
    await events.waitUntilReady();
    await worker.waitUntilReady();
    const r = await fetch(`${SERVER}/api/digest`, as("3", { method: "POST" }));
    expect(r.status).toBe(202);
    const queued = await Job.fromId(digests(), (await r.json()).id);
    expect(await queued?.waitUntilFinished(events, 30_000)).toEqual(SERVICE);
    // queued here, acting for user 2: the worker still acts for its service
    const mine = await actingAs("2", () => digests().add("digest", {}));
    expect(await mine.waitUntilFinished(events, 30_000)).toEqual(SERVICE);
    await until(() => after.length === 2);
    expect(after).toEqual(["nobody", "nobody"]);
  } finally {
    await worker.close();
    await events.close();
  }
});

// after(): once the response is sent, as the request's user (read from the request, as every transaction is) and as
// a service (job()); the requests right after, on the server's one connection, see only their own rows
test("after(): work once the response is sent signs in as the request's user or a service, and carries over to no request", async () => {
  const users = ["1", "2", "3", ""];
  const key = (u: string) => `${Date.now()}-${u || "nobody"}`;
  const keys = users.map(key);
  const sent = await Promise.all(users.map((u, i) =>
    fetch(`${SERVER_ONE}/api/after`, as(u || null, { method: "POST", body: JSON.stringify({ key: keys[i] }) }))));
  expect(sent.map((r) => r.status)).toEqual(users.map(() => 202));
  const next = [...users, ...users];
  const got = await Promise.all(next.map((u) => fetch(`${SERVER_ONE}/api/notes`, as(u || null)).then((r) => r.json())));
  expect(got).toEqual(next.map((u) => EXPECTED[u]));
  for (const [i, u] of users.entries()) {
    const url = `${SERVER_ONE}/api/after/${encodeURIComponent(keys[i])}`;
    await until(async () => (await fetch(url)).status === 200);
    expect(await (await fetch(url)).json(), u).toEqual({
      user: { who: u ? `user ${u}` : "nobody", notes: EXPECTED[u] },
      service: { who: "service 1", projects: [1, 3] },
    });
  }
});

// ... and in a page Next lets after() read nothing of the request (its headers, its cookies): the work fails, in Next's
// words, unless the page reads the user while it renders (app/later)
test("after(): in a page, the work can't read the request, and fails saying so", async () => {
  const r = await fetch(`${SERVER}/later-unread`, as("1"));
  expect([r.status, await r.text()]).toEqual([200, expect.stringContaining("the work after it fails")]);
  const said = "used `headers()` inside `after()` while rendering. This is not supported.";
  await until(() => readFileSync(SERVER_LOG, "utf8").includes(said));
  expect(readFileSync(SERVER_LOG, "utf8")).toContain(said);
});

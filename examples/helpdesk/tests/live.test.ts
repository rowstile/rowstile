// Live: each person's shapes of the tickets and comments, through the app's shape route and Electric, as the
// pages follow them (src/live.ts applies the move-outs Electric sends). What arrives and what leaves is the sync
// index's, which the policy keeps: nothing here filters.
import { afterEach, describe, expect, test } from "vitest";
import { ShapeStream, isControlMessage } from "@electric-sql/client";
import { Rows } from "@/live.ts";
import { ACME, SERVER, as, ids, tickets, type Person } from "./people.ts";

const open: AbortController[] = [];
afterEach(() => { for (const c of open.splice(0)) c.abort(); });

/** A person's shape, live: its rows as they arrive and leave. */
function follow(person: Person, table: "tickets" | "comments") {
  const stop = new AbortController();
  open.push(stop);
  const rows = new Rows();
  let ready = false;
  const waiting = new Set<() => void>();
  const stream = new ShapeStream({ url: `${SERVER}/api/shapes/${table}`, headers: { cookie: person.cookie() }, signal: stop.signal });
  stream.subscribe((messages) => {
    for (const m of messages) {
      rows.apply(m);
      if (isControlMessage(m) && m.headers.control === "up-to-date") ready = true;
    }
    if (ready) for (const w of waiting) w();
  }, () => {});
  const until = (ok: (ids: string[]) => boolean, what: string) => new Promise<void>((resolve, reject) => {
    const check = () => { if (ok(rows.ids())) { clearTimeout(timer); waiting.delete(check); resolve(); } };
    const timer = setTimeout(() => { waiting.delete(check); reject(new Error(`${table}: ${what} never came (it holds ${rows.ids()})`)); }, 30_000);
    waiting.add(check);
    if (ready) check();
  });
  return { rows, until, has: (id: string) => until((l) => l.includes(id), `${id} in it`), lacks: (id: string) => until((l) => !l.includes(id), `${id} gone`) };
}

describe("live", () => {
  test("nobody gets no shape, and a session viewing as someone gets none either", async () => {
    expect((await fetch(`${SERVER}/api/shapes/tickets?offset=-1`)).status).toBe(401);
    const ann = await as("ann@acme.test");
    await ann.send("POST", "/api/view-as", { user: ids.cy });
    const r = await fetch(`${SERVER}/api/shapes/tickets?offset=-1`, { headers: { cookie: ann.cookie() } });
    expect(r.status).toBe(403);
    await ann.send("POST", "/api/view-as", { user: null });
  });

  test("a customer's shape: their tickets and their org's, never another workspace's", async () => {
    const peter = await as("peter@initech.test");
    const live = follow(peter, "tickets");
    await live.until((l) => l.includes(tickets.invoice) && l.includes(tickets.printer), "Peter's and Milton's tickets");
    expect(live.rows.ids()).not.toContain(tickets.globex);
  });

  test("copied in: the ticket arrives live, and leaves when the share does", async () => {
    const cy = await as("cy@mail.test");
    const made = await cy.send("POST", "/api/tickets", { workspaceId: ACME, subject: "Live one", body: "hello", requesterId: ids.cy });
    expect(made.status).toBe(201);
    const t: string = made.json.id;
    const peter = await as("peter@initech.test");
    const live = follow(peter, "tickets");
    await live.until((l) => l.includes(tickets.invoice), "the start");
    expect(live.rows.ids()).not.toContain(t);
    expect((await cy.send("POST", `/api/tickets/${t}/cc`, { user: ids.peter })).status).toBe(204);
    await live.has(t);
    expect((await cy.send("DELETE", `/api/tickets/${t}/cc`, { user: ids.peter })).status).toBe(204);
    await live.lacks(t);
  });

  test("an internal note reaches those who work the ticket, never the customer", async () => {
    const al = await as("al@acme.test");
    const peter = await as("peter@initech.test");
    const agent = follow(al, "comments");
    const customer = follow(peter, "comments");
    await customer.until((l) => l.length > 0, "the customer's comments");
    const note = await al.send("POST", `/api/tickets/${tickets.invoice}/comments`, { body: "live note", internal: true });
    expect(note.status).toBe(201);
    const reply = await al.send("POST", `/api/tickets/${tickets.invoice}/comments`, { body: "live reply" });
    await agent.has(note.json.id);
    await customer.has(reply.json.id);
    expect(customer.rows.ids()).not.toContain(note.json.id);
  });

  test("the vendor's staff: a ticket arrives when they break the glass", async () => {
    const ann = await as("ann@acme.test");
    await ann.send("POST", "/api/support-access", { workspaceId: ACME, staffId: ids.sam, days: 1 });
    const sam = await as("sam@vendor.test");
    const live = follow(sam, "tickets");
    const before = live.until(() => true, "anything");
    await before;
    expect(live.rows.ids()).not.toContain(tickets.printer);
    expect((await sam.send("POST", `/api/tickets/${tickets.printer}/break-glass`, { reason: "case 9" })).status).toBe(204);
    await live.has(tickets.printer);
  });

  test("the vendor's staff: when break glass ends, the ticket and its internal notes leave", async () => {
    const sam = await as("sam@vendor.test");
    const live = follow(sam, "tickets");
    const notes = follow(sam, "comments");
    await live.until(() => true, "the start");
    expect(live.rows.ids()).not.toContain(tickets.invoice);
    // (the support access the test above gave)
    expect((await sam.send("POST", `/api/tickets/${tickets.invoice}/break-glass`, { reason: "case 10", seconds: 5 })).status).toBe(204);
    await live.has(tickets.invoice);
    const note: string = (await sam.get(`/api/tickets/${tickets.invoice}`)).json.comments.find((c: { internal: boolean }) => c.internal).id;
    await notes.has(note);
    // the share ends with no write: the sync index learns of it at the next authz.sync_tick() (jobs/sync-tick.ts)
    await live.lacks(tickets.invoice);
    await notes.lacks(note);
    expect((await sam.get(`/api/tickets/${tickets.invoice}`)).status).toBe(404);
  });
});

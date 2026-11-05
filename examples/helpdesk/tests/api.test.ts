// The helpdesk's API, as its people use it: each check signs in as someone of the demo (db/seed.sql) and asks
// the app, which asks the database. The app has no permission checks: every answer here is the policy's.
import { describe, expect, test } from "vitest";
import { ACME, EMAIL_INTAKE, GLOBEX, SERVER, as, ids, tickets } from "./people.ts";

const subjects = (list: { subject: string }[]) => list.map((t) => t.subject).sort();

describe("workspaces", () => {
  test("a workspace's tickets are its own", async () => {
    const bob = await as("bob@globex.test");
    expect(subjects((await bob.get("/api/tickets")).json)).toEqual(["Globex: export to CSV"]);
    expect((await bob.get(`/api/tickets/${tickets.invoice}`)).status).toBe(404);
    expect((await bob.get(`/api/people/${ids.peter}`)).status).toBe(404);
    const ann = await as("ann@acme.test");
    expect((await ann.get("/api/tickets")).json).toHaveLength(3);
    expect((await ann.get(`/api/tickets/${tickets.globex}`)).status).toBe(404);
  });

  test("a ticket for another workspace's customer is refused", async () => {
    const ann = await as("ann@acme.test");
    const r = await ann.send("POST", "/api/tickets", { workspaceId: GLOBEX, subject: "x", body: "x", requesterId: ids.xu });
    expect(r.status).toBe(403);
  });
});

describe("agents and teams", () => {
  test("an agent sees the workspace's tickets, and works those of their teams", async () => {
    const oz = await as("oz@acme.test");
    expect((await oz.get("/api/tickets")).json).toHaveLength(3);
    const invoice = (await oz.get(`/api/tickets/${tickets.invoice}`)).json;
    expect(invoice.perms).toContain("view");
    expect(invoice.perms).not.toContain("work");
    // the internal note is for those who work it
    expect(invoice.comments.map((c: { internal: boolean }) => c.internal)).toEqual([false, false]);
    const al = await as("al@acme.test");
    const asAl = (await al.get(`/api/tickets/${tickets.invoice}`)).json;
    expect(asAl.perms).toContain("work");
    expect(asAl.comments).toHaveLength(3);
  });

  test("an internal note from someone who doesn't work the ticket is refused, and says why", async () => {
    const oz = await as("oz@acme.test");
    const r = await oz.send("POST", `/api/tickets/${tickets.invoice}/comments`, { body: "x", internal: true });
    expect(r.status).toBe(403);
    expect(r.json.why.join("\n")).toContain("ticket.work");
  });

  test("a lead works the teams inside theirs", async () => {
    const lea = await as("lea@acme.test");
    expect((await lea.get(`/api/tickets/${tickets.printer}`)).json.perms).toContain("work");
    expect((await lea.get(`/api/tickets/${tickets.password}`)).json.perms).not.toContain("work");
  });

  test("an agent hands a ticket on, and still sees it after", async () => {
    const lea = await as("lea@acme.test");
    expect((await lea.send("PATCH", `/api/tickets/${tickets.printer}`, { assigneeId: ids.oz })).status).toBe(200);
    const oz = await as("oz@acme.test");
    expect((await oz.send("PATCH", `/api/tickets/${tickets.printer}`, { teamId: null, assigneeId: ids.al })).status).toBe(200);
    const after = (await oz.get(`/api/tickets/${tickets.printer}`)).json;
    expect(after.perms).toContain("view");
    expect(after.perms).not.toContain("work");
  });
});

describe("customers", () => {
  test("a customer sees their tickets, and their org's where it shares them, without internal notes", async () => {
    const peter = await as("peter@initech.test");
    expect(subjects((await peter.get("/api/tickets")).json)).toEqual(["Invoice 4410 charged twice", "The printer says PC LOAD LETTER"]);
    const invoice = (await peter.get(`/api/tickets/${tickets.invoice}`)).json;
    expect(invoice.comments).toHaveLength(2);
    expect(invoice.comments.some((c: { internal: boolean }) => c.internal)).toBe(false);
    // and who answered them: the workspace's agents are seen by its people
    expect(invoice.comments.map((c: { author: { name: string } | null }) => c.author?.name)).toEqual(["Peter Gibbons", "Al Billing"]);
    const cy = await as("cy@mail.test");
    expect(subjects((await cy.get("/api/tickets")).json)).toEqual(["Password reset never arrives"]);
  });

  test("a requester solves and reopens, and can't set anything else", async () => {
    const cy = await as("cy@mail.test");
    expect((await cy.send("PATCH", `/api/tickets/${tickets.password}`, { status: "solved" })).status).toBe(200);
    expect((await cy.send("PATCH", `/api/tickets/${tickets.password}`, { status: "open" })).status).toBe(200);
    expect((await cy.send("PATCH", `/api/tickets/${tickets.password}`, { status: "pending" })).status).toBe(403);
    expect((await cy.send("PATCH", `/api/tickets/${tickets.password}`, { assigneeId: ids.al })).status).toBe(403);
  });

  test("the agents' notes on a customer: agents read them, the customer doesn't", async () => {
    const ann = await as("ann@acme.test");
    expect((await ann.get(`/api/people/${ids.peter}`)).json.notes).toBe("Prefers a call back");
    const peter = await as("peter@initech.test");
    expect((await peter.get(`/api/people/${ids.peter}`)).json.notes).toBeNull();
    expect((await peter.send("PATCH", `/api/people/${ids.peter}`, { notes: "nice" })).status).toBe(403);
    expect((await peter.send("PATCH", `/api/people/${ids.peter}`, { name: "Peter G." })).status).toBe(200);
  });

  test("copying someone in: of the workspace, never of another", async () => {
    const cy = await as("cy@mail.test");
    expect((await cy.send("POST", `/api/tickets/${tickets.password}/cc`, { user: ids.milton })).status).toBe(204);
    const milton = await as("milton@initech.test");
    expect((await milton.get(`/api/tickets/${tickets.password}`)).json.perms).toContain("reply");
    expect((await cy.send("POST", `/api/tickets/${tickets.password}/cc`, { user: ids.xu })).status).toBe(403);
    const xu = await as("xu@mail.test");
    expect((await xu.get(`/api/tickets/${tickets.password}`)).status).toBe(404);
  });
});

describe("admins", () => {
  test("a custom role works the tickets it is given on, for the workspace's own agents only", async () => {
    const ann = await as("ann@acme.test");
    const role = (await ann.send("POST", "/api/roles", { workspaceId: ACME, name: "Escalations", perms: ["work"] })).json.id;
    expect((await ann.send("POST", `/api/tickets/${tickets.password}/roles`, { role, user: ids.oz })).status).toBe(204);
    const oz = await as("oz@acme.test");
    expect((await oz.get(`/api/tickets/${tickets.password}`)).json.perms).toContain("work");
    // the API takes any id: given to someone of another workspace, it gives them nothing
    expect((await ann.send("POST", `/api/tickets/${tickets.password}/roles`, { role, user: ids.bob })).status).toBe(204);
    const bob = await as("bob@globex.test");
    expect((await bob.get(`/api/tickets/${tickets.password}`)).status).toBe(404);
    // and only an admin makes roles
    expect((await oz.send("POST", "/api/roles", { workspaceId: ACME, name: "Mine", perms: ["work"] })).status).toBe(403);
  });

  test("an admin views the app as someone of their workspace, read-only", async () => {
    const ann = await as("ann@acme.test");
    expect((await ann.send("POST", "/api/view-as", { user: ids.cy })).status).toBe(204);
    expect(subjects((await ann.get("/api/tickets")).json)).toEqual(["Password reset never arrives"]);
    const write = await ann.send("POST", `/api/tickets/${tickets.password}/comments`, { body: "as Cy" });
    expect(write.status).toBe(403);
    expect((await ann.send("POST", "/api/view-as", { user: null })).status).toBe(204);
    expect((await ann.get("/api/tickets")).json).toHaveLength(3);
    // not someone of another workspace, and not as an agent
    expect((await ann.send("POST", "/api/view-as", { user: ids.bob })).status).toBe(403);
    const al = await as("al@acme.test");
    expect((await al.send("POST", "/api/view-as", { user: ids.cy })).status).toBe(403);
  });
});

describe("the vendor's staff", () => {
  test("by break glass only, where the workspace lets them in", async () => {
    const sam = await as("sam@vendor.test");
    expect((await sam.get("/api/tickets")).json).toEqual([]);
    expect((await sam.send("POST", `/api/tickets/${tickets.password}/break-glass`, { reason: "case 7" })).status).toBe(403);
    const ann = await as("ann@acme.test");
    expect((await ann.send("POST", "/api/support-access", { workspaceId: ACME, staffId: ids.sam, days: 30 })).status).toBe(403);
    expect((await ann.send("POST", "/api/support-access", { workspaceId: ACME, staffId: ids.cy, days: 1 })).status).toBe(403);
    expect((await ann.send("POST", "/api/support-access", { workspaceId: ACME, staffId: ids.sam, days: 1 })).status).toBe(204);
    expect((await sam.send("POST", `/api/tickets/${tickets.password}/break-glass`, { reason: "case 7" })).status).toBe(204);
    expect((await sam.get(`/api/tickets/${tickets.password}`)).json.perms).toContain("work");
    expect((await sam.get(`/api/tickets/${tickets.invoice}`)).status).toBe(404);
  });
});

describe("the email intake", () => {
  test("its key makes tickets and customers in its workspace, and nothing more", async () => {
    const ann = await as("ann@acme.test");
    const { key } = (await ann.send("POST", `/api/integrations/${EMAIL_INTAKE}/keys`, { name: "mail server" })).json;
    expect(key).toBeTruthy();
    const mail = (json: unknown) => fetch(`${SERVER}/api/intake`, {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${key}` }, body: JSON.stringify(json),
    });
    const made = await mail({ workspaceId: ACME, from: "dee@mail.test", name: "Dee", subject: "Locked out", body: "Help" });
    expect(made.status, await made.clone().text()).toBe(201);
    const { ticket } = (await made.json()) as { ticket: string };
    expect(subjects((await ann.get("/api/tickets")).json)).toContain("Locked out");
    expect((await ann.get(`/api/tickets/${ticket}`)).json.comments[0].body).toBe("Help");
    // another workspace: refused, whatever the mail says
    expect((await mail({ workspaceId: GLOBEX, from: "x@mail.test", name: "X", subject: "x", body: "x" })).status).toBe(403);
    // and no key: no one
    const none = await fetch(`${SERVER}/api/intake`, { method: "POST", body: "{}" });
    expect(none.status).toBe(401);
    // an agent can't make the intake a key
    const al = await as("al@acme.test");
    expect((await al.send("POST", `/api/integrations/${EMAIL_INTAKE}/keys`, { name: "mine" })).status).toBe(403);
  });
});

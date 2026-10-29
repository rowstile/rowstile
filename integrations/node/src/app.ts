// The app: Express 5, each request acting for its user. The routes check nothing themselves: the database
// filters what they read and refuses what the user may not write, and the error handler answers with the problem.
import express, { type NextFunction, type Request, type Response } from "express";
import { asc, eq } from "drizzle-orm";
import { actingAs, current, problemOf } from "@rowstile/client";
import { expect as drizzleExpect, inIds } from "@rowstile/drizzle";
import { userOf } from "./auth.js";                   // the session's user: your own, or Passport's req.user
import { db, pgjs, sql } from "./db.js";
import { folders, inbox, notes, projects } from "./schema.js";

export const app = express();
app.use(express.json());
// every transaction a request begins signs in as its user (none: nobody, who sees only what `anyone` may)
app.use((req, _res, next) => actingAs(userOf(req), next));

const id = (req: Request) => Number(req.params.id);
const me = () => Number(current()?.id);               // who the request acts for, as the tables' key

// lists show only what the user may see: on Drizzle, on node-postgres, on postgres.js
app.get("/api/notes", async (_req, res) => {
  const rows = await db.transaction((tx) => tx.select({ id: notes.id }).from(notes).orderBy(asc(notes.id)));
  res.json(rows.map((n) => n.id));
});

app.get("/api/projects", async (_req, res) => {
  res.json((await sql.query<{ id: number }>("SELECT id FROM app.projects ORDER BY id")).rows.map((p) => p.id));
});

app.get("/api/pgjs/projects", async (_req, res) => {
  const rows = await pgjs.begin((tx) => tx<{ id: number }[]>`SELECT id FROM app.projects ORDER BY id`);
  res.json(rows.map((p) => p.id));
});

// a create the insert rule may refuse: 403 with the rule and why
app.post("/api/notes", async (req, res) => {
  const { project_id, body } = req.body as { project_id: number; body: string };
  const [note] = await db.transaction((tx) =>
    tx.insert(notes).values({ projectId: project_id, authorId: me(), body }).returning({ id: notes.id }));
  res.status(201).json(note);
});

// an update the rules may refuse: a hidden note is 404, one the user may not edit 403 with the reason
app.patch("/api/notes/:id", async (req, res) => {
  const { body } = req.body as { body: string };
  await db.transaction(async (tx) => drizzleExpect(tx,
    await tx.update(notes).set({ body }).where(eq(notes.id, id(req))).returning({ id: notes.id }), "app.notes", "update", id(req)));
  res.json({ id: id(req) });
});

app.delete("/api/notes/:id", async (req, res) => {
  await db.transaction(async (tx) => drizzleExpect(tx,
    await tx.delete(notes).where(eq(notes.id, id(req))).returning({ id: notes.id }), "app.notes", "delete", id(req)));
  res.status(204).end();
});

// an insert the user may not read back (RETURNING needs the select rule): 403, naming the select rule
app.post("/api/inbox", async (req, res) => {
  const { recipient_id, body } = req.body as { recipient_id: number; body: string };
  const [message] = await db.transaction((tx) =>
    tx.insert(inbox).values({ senderId: me(), recipientId: recipient_id, body }).returning({ id: inbox.id }));
  res.status(201).json(message);
});

// ... and the same insert, not read back: the insert rule alone
app.post("/api/inbox/quietly", async (req, res) => {
  const { recipient_id, body } = req.body as { recipient_id: number; body: string };
  await db.transaction((tx) => tx.insert(inbox).values({ senderId: me(), recipientId: recipient_id, body }));
  res.status(202).end();
});

app.get("/api/inbox", async (_req, res) => {
  res.json((await db.transaction((tx) => tx.select({ id: inbox.id }).from(inbox).orderBy(asc(inbox.id)))).map((m) => m.id));
});

app.get("/api/inbox/:id/perms", async (req, res) => {
  res.json(await sql.perms("message", id(req)));
});

// queries by permission: a set check in the query, and one call for a list's buttons
app.get("/api/projects/editable", async (_req, res) => {
  const rows = await db.transaction((tx) =>
    tx.select({ id: projects.id }).from(projects).where(inIds(projects.id, "project", "edit")).orderBy(asc(projects.id)));
  res.json(rows.map((p) => p.id));
});

app.get("/api/projects/buttons", async (_req, res) => {
  res.json(await sql.transaction(async (c) => {
    const ids = (await c.query<{ id: number }>("SELECT id FROM app.projects ORDER BY id")).rows.map((p) => p.id);
    return sql.permsOf("project", ids);                // in the same transaction
  }));
});

// a page of the projects the user may see (a page size the database turns down: 400)
app.get("/api/projects/visible", async (req, res) => {
  res.json(await sql.list("project", "view", { limit: Number(req.query.limit ?? 50) }));
});

// sharing: who may share is the policy's (viewer is shared by edit), and the database says no
app.get("/api/projects/:id/shares", async (req, res) => {
  res.json((await sql.listShares("project", id(req))).map((s) => ({ relation: s.relation, user: s.subject_id })));
});

app.post("/api/projects/:id/shares", async (req, res) => {
  const { user, relation = "viewer" } = req.body as { user: number; relation?: "viewer" };
  await sql.share("project", id(req), relation, "user", user);
  res.status(204).end();
});

app.delete("/api/projects/:id/shares", async (req, res) => {
  const { user } = req.body as { user: number };
  await sql.unshare("project", id(req), "viewer", "user", user);
  res.status(204).end();
});

// asking for access (someone signed in, with a reason: the database says what is missing)
app.post("/api/projects/:id/requests", async (req, res) => {
  const { reason } = req.body as { reason: string };
  res.status(201).json({ id: await sql.requestAccess("project", id(req), "viewer", reason) });
});

// a folder moved inside one of its own subfolders: 409, in the database's words
app.patch("/api/folders/:id", async (req, res) => {
  const { parent_id } = req.body as { parent_id: number | null };
  await db.transaction(async (tx) => drizzleExpect(tx,
    await tx.update(folders).set({ parentId: parent_id }).where(eq(folders.id, id(req))).returning({ id: folders.id }),
    "app.folders", "update", id(req)));
  res.json({ id: id(req) });
});

// API keys: a request with one signs in with it (a key the database doesn't know: 401); a session signed in with
// a key that may only read may not make another (403); a key that isn't the user's can't be revoked (404)
const withKey = async (req: Request, c: { query(text: string, values?: unknown[]): Promise<unknown> }) => {
  const key = req.get("x-api-key");
  if (key !== undefined) await c.query("SELECT authz.login_key($1)", [key]);
};

app.get("/api/key/projects", async (req, res) => {
  res.json(await sql.transaction(async (c) => {
    await withKey(req, c);
    return (await c.query<{ id: number }>("SELECT id FROM app.projects ORDER BY id")).rows.map((p) => p.id);
  }));
});

app.post("/api/keys", async (req, res) => {
  const { name } = req.body as { name: string };
  res.status(201).json(await sql.transaction(async (c) => {
    await withKey(req, c);
    return { key: (await c.query<{ k: string }>("SELECT authz.create_api_key($1) AS k", [name])).rows[0]?.k };
  }));
});

app.delete("/api/keys/:id", async (req, res) => {
  await sql.query("SELECT 1 AS ok FROM authz.revoke_api_key($1::bigint)", [id(req)]);
  res.status(204).end();
});

// a refusal is 403 with the rule and why, a hidden row 404, and the database's other answers as their codes'
// pages say (rowstile help AZ708); anything else is the app's mistake: Express's own 500
export function problems(err: unknown, _req: Request, res: Response, next: NextFunction): void {
  const problem = problemOf(err);
  if (problem) res.status(problem.status).type("application/problem+json").json(problem);
  else next(err);
}

app.use(problems);

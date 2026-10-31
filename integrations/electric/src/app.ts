// The app: Express 5. Its shape routes stand in front of Electric: each asks the database who the request is, then
// hands Electric the shape the policy gives them (@rowstile/client's electricShape, on the constants rowstile client
// electric writes). Its other routes write through the database, which refuses what the user may not write.
import { Readable } from "node:stream";
import express, { type NextFunction, type Request as ExpressRequest, type Response as ExpressResponse } from "express";
import { actingAs, electricShape, problemOf, syncPrincipal, type ElectricShape } from "@rowstile/client";
import { KEY, USER, keyOf, userOf } from "./auth.js";
import { sql } from "./db.js";
import { shapes } from "./shapes.gen.js";

export const app = express();

// who the request is, asked of the database the app's way: an API key signs in with it, else the session's user
export async function signedIn(req: Request) {
  const key = keyOf(req.headers);
  if (key !== null) {
    return sql.transaction(async (c) => {
      await c.query("SELECT authz.login_key($1)", [key]);
      return syncPrincipal(c);
    });
  }
  return actingAs(userOf(req.headers), () => sql.transaction((c) => syncPrincipal(c)));
}

const electric = { url: process.env.ELECTRIC_URL ?? "", secret: process.env.ELECTRIC_SECRET, signedIn, vary: [USER, KEY] };
// a Map, so that a name such as constructor finds no route
export const routes = new Map<string, (req: Request) => Promise<Response>>([
  ["files", electricShape(shapes["app.files"], electric)],
  ["folders", electricShape(shapes["app.folders"], electric)],
  // the policy masks the notes' body: the columns to sync leave it out
  ["notes", electricShape(shapes["app.notes"] satisfies ElectricShape, { ...electric, columns: ["id", "file_id", "author_id"] })],
]);

/** Express's request as fetch's, and fetch's response back: Express 5 runs on Node's own http. */
async function fetched(handler: (req: Request) => Promise<Response>, req: ExpressRequest, res: ExpressResponse) {
  const gone = new AbortController();
  res.on("close", () => gone.abort());
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    for (const v of Array.isArray(value) ? value : [value ?? ""]) headers.append(name, v);
  }
  const body = req.method === "GET" ? undefined : (Readable.toWeb(req) as ReadableStream<Uint8Array>);
  const answer = await handler(new Request(`http://${req.get("host")}${req.originalUrl}`,
    { method: req.method, headers, body, signal: gone.signal, duplex: "half" } as RequestInit));
  res.status(answer.status);
  answer.headers.forEach((value, name) => res.setHeader(name, value));
  if (answer.body) Readable.fromWeb(answer.body as import("node:stream/web").ReadableStream).pipe(res);
  else res.end();
}

app.all("/shapes/:table", async (req, res, next) => {
  const handler = routes.get(String(req.params.table));
  if (typeof handler !== "function") return next();
  await fetched(handler, req, res);
});

// writes through the app, as the request's user: they arrive in the shapes of those who may read them
app.use(express.json());
app.use((req, _res, next) => actingAs(req.get(USER) ?? null, next));

app.post("/api/files", async (req, res) => {
  const { id, folder_id, name } = req.body as { id: number; folder_id: number; name: string };
  await sql.query("INSERT INTO app.files (id, folder_id, owner_id, name) VALUES ($1, $2, authz.uid(), $3)", [id, folder_id, name]);
  res.status(201).json({ id });
});

app.patch("/api/files/:id", async (req, res) => {
  const { name } = req.body as { name: string };
  const id = Number(req.params.id);
  await sql.transaction(async (c) => sql.expect(await c.query("UPDATE app.files SET name = $1 WHERE id = $2", [name, id]), "app.files", "update", id));
  res.json({ id });
});

// a refusal is 403 with the rule and why, a hidden row 404, a login refused 401 (rowstile help AZ703); anything
// else is the app's mistake: Express's own 500
export function problems(err: unknown, _req: ExpressRequest, res: ExpressResponse, next: NextFunction): void {
  const problem = problemOf(err);
  if (problem) res.status(problem.status).type("application/problem+json").json(problem);
  else next(err);
}

app.use(problems);

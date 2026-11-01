// The app: Express 5. PowerSync's clients ask it for a token (POST /api/powersync/token), which the service checks
// (HS256, the key both share); the app asks the database who the request is first (@rowstile/client's
// syncPrincipal): nobody is 401, and a session limited by scopes or viewing as someone 403, since the sync index holds
// what each principal may read, without scopes. The token names the principal (sub, and principal_type), whose keys
// the streams read (powersync/sync-config.yaml, which rowstile client powersync writes). The clients' writes come
// back through the app's own routes, signed in as the request's user: the database refuses what they may not write.
import { createHmac } from "node:crypto";
import express, { type NextFunction, type Request as ExpressRequest, type Response as ExpressResponse } from "express";
import { actingAs, problemOf, syncPrincipal, type SyncPrincipal } from "@rowstile/client";
import { USER, keyOf, userOf } from "./auth.js";
import { sql } from "./db.js";

export const app = express();

/** The key the service checks tokens with (client_auth.jwks in its config): an HS256 secret only the two hold. */
export const TOKEN_SECRET = process.env.POWERSYNC_TOKEN_SECRET ?? "";
export const TOKEN_KID = "rowstile-conformance";
const b64 = (s: string) => Buffer.from(s).toString("base64url");

/** A token for the principal, as PowerSync reads it: sub its id, principal_type its type, for an hour. */
export function token(who: { type: string; id: string }, now = Math.floor(Date.now() / 1000)): string {
  const head = b64(JSON.stringify({ alg: "HS256", typ: "JWT", kid: TOKEN_KID }));
  const body = b64(JSON.stringify({ sub: who.id, principal_type: who.type, aud: "powersync", iat: now, exp: now + 3600 }));
  const sig = createHmac("sha256", TOKEN_SECRET).update(`${head}.${body}`).digest("base64url");
  return `${head}.${body}.${sig}`;
}

/** Who the request is, asked of the database the app's way: an API key signs in with it, else the session's user. */
export async function signedIn(headers: Headers): Promise<SyncPrincipal> {
  const key = keyOf(headers);
  if (key !== null) {
    return sql.transaction(async (c) => {
      await c.query("SELECT authz.login_key($1)", [key]);
      return syncPrincipal(c);
    });
  }
  return actingAs(userOf(headers), () => sql.transaction((c) => syncPrincipal(c)));
}

const headersOf = (req: ExpressRequest) => {
  const h = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    for (const v of Array.isArray(value) ? value : [value ?? ""]) h.append(name, v);
  }
  return h;
};

app.use(express.json());

app.post("/api/powersync/token", async (req, res, next) => {
  try {
    const who = await signedIn(headersOf(req));
    if (who.id === null) {
      res.status(401).json({ error: "Unauthorized", detail: "sign in to sync" });
      return;
    }
    if (who.limited) {
      res.status(403).json({ error: "Forbidden", detail: "a session limited by scopes, or viewing as someone, can't sync" });
      return;
    }
    res.json({ token: token({ type: who.type, id: who.id }) });
  } catch (e) {
    next(e);
  }
});

// the clients' writes (their upload queue), as the request's user: they arrive in the streams of those who may read them
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

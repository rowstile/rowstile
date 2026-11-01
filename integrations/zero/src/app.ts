// The app: Express 5, with Zero's two endpoints, which zero-cache calls with the client's token. Each asks the
// database who the request is first (@rowstile/client's syncPrincipal): nobody is 401 and a session limited by
// scopes or viewing as someone 403, which Zero shows the client as needs-auth; the sync index holds what each
// principal may read, without scopes. The query endpoint returns each query's ZQL with the index's filter for that
// principal (src/queries.ts), its context made here, never the client's. The mutate endpoint runs each mutator in a
// transaction signed in as the request's user, so the database's rules decide what it may write.
import express, { type Request as ExpressRequest, type Response as ExpressResponse } from "express";
import { mustGetMutator, mustGetQuery } from "@rocicorp/zero";
import { handleMutateRequest, handleQueryRequest } from "@rocicorp/zero/server";
import { zeroNodePg } from "@rocicorp/zero/server/adapters/pg";
import { actAs, actingAs, problemOf, syncPrincipal, type SyncPrincipal } from "@rowstile/client";
import { tokenOf, type Token } from "./auth.js";
import { pool, sql } from "./db.js";
import { mutators } from "./mutators.js";
import { queries, type Ctx } from "./queries.js";
import { schema, writeSchema } from "./schema.js";

export const app = express();
// (on the app's own tables, which the mutators write: the app role may read nothing of the sync index's)
const zeroDb = zeroNodePg(writeSchema as unknown as typeof schema, pool);

/** Who the token is, asked of the database the app's way: an API key signs in with it, else the token's user. */
export async function signedIn(token: Token): Promise<SyncPrincipal> {
  if (token !== null && "key" in token) {
    return sql.transaction(async (c) => {
      await c.query("SELECT authz.login_key($1)", [token.key]);
      return syncPrincipal(c);
    });
  }
  return actingAs(token?.user ?? null, () => sql.transaction((c) => syncPrincipal(c)));
}

/** Express's request as fetch's: Zero's handlers read the URL's parameters and the JSON body. */
function fetchRequest(req: ExpressRequest): Request {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    for (const v of Array.isArray(value) ? value : [value ?? ""]) headers.append(name, v);
  }
  return new Request(`http://${req.get("host")}${req.originalUrl}`,
    { method: "POST", headers, body: JSON.stringify(req.body) });
}

/** The principal a request's queries and mutators are for, or the answer that refuses it (401, 403). */
async function whoAsks(req: ExpressRequest, res: ExpressResponse): Promise<{ token: Token; ctx: Ctx } | null> {
  const token = tokenOf(fetchRequest(req).headers);
  let who: SyncPrincipal;
  try {
    who = await signedIn(token);
  } catch (e) {
    // a login the database refuses (a key that isn't one: AZ703) is its problem's status, 401, in its words
    const problem = problemOf(e);
    if (problem === null) throw e;
    res.status(problem.status).json({ error: problem.title, detail: problem.detail, code: problem.code });
    return null;
  }
  if (who.id === null) {
    res.status(401).json({ error: "Unauthorized", detail: "sign in to sync" });
    return null;
  }
  if (who.limited) {
    res.status(403).json({ error: "Forbidden", detail: "a session limited by scopes, or viewing as someone, can't sync" });
    return null;
  }
  return { token, ctx: { type: who.type as Ctx["type"], id: who.id } };
}

app.use(express.json());

app.post("/api/zero/query", async (req, res) => {
  const asked = await whoAsks(req, res);
  if (asked === null) return;
  const result = await handleQueryRequest({
    handler: (name, args) => mustGetQuery(queries, name).fn({ args, ctx: asked.ctx }),
    schema,
    request: fetchRequest(req),
    userID: asked.ctx.id,
  });
  res.json(result);
});

app.post("/api/zero/mutate", async (req, res) => {
  const asked = await whoAsks(req, res);
  if (asked === null) return;
  const { token, ctx } = asked;
  const result = await handleMutateRequest({
    dbProvider: zeroDb,
    handler: (transact) =>
      transact(async (tx, name, args) => {
        // the transaction signed in first, as the request's key or user: what the mutator writes, the rules judge
        if (token !== null && "key" in token) await tx.dbTransaction.query("SELECT authz.login_key($1)", [token.key]);
        else {
          const signIn = actAs({ type: ctx.type, id: ctx.id });
          await tx.dbTransaction.query(signIn.text, signIn.values);
        }
        return mustGetMutator(mutators, name).fn({ args, tx, ctx });
      }),
    request: fetchRequest(req),
    userID: ctx.id,
  });
  res.json(result);
});

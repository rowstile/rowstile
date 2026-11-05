// A custom role of the workspace given on a ticket: a share of the relation role:<id>. A role counts only for the
// workspace's own agents, whomever it is given to.
import { route } from "@rowstile/next";
import { inTx } from "@/db.ts";
import { body, noContent } from "@/http.ts";

type Params = { params: Promise<{ id: string }> };

export const POST = route(async (req: Request, { params }: Params) => {
  const { role, user } = await body<{ role: number; user: string }>(req);
  const { id } = await params;
  // a role's relation isn't one of the policy's names, so not one the typed share takes: SQL's authz.share
  await inTx((tx) => tx.$executeRaw`SELECT authz.share('ticket', ${id}::text, ${`role:${role}`}, 'user', ${user}::text)`);
  return noContent();
});

// Copying someone in: a share of the relation cc. Who may give it, and to whom (someone of the ticket's own
// workspace), is the policy's: anyone else gets a 403. Through inTx, as every route: while an admin views the app
// as someone, it is refused (view-as is read-only).
import { route } from "@rowstile/next";
import { inTx } from "@/db.ts";
import { body, noContent } from "@/http.ts";

type Params = { params: Promise<{ id: string }> };

export const POST = route(async (req: Request, { params }: Params) => {
  const { user } = await body<{ user: string }>(req);
  const { id } = await params;
  await inTx((tx) => tx.$executeRaw`SELECT authz.share('ticket', ${id}::text, 'cc', 'user', ${user}::text)`);
  return noContent();
});

// and taking them off it: an unshare, which only someone who may share it may make
export const DELETE = route(async (req: Request, { params }: Params) => {
  const { user } = await body<{ user: string }>(req);
  const { id } = await params;
  await inTx((tx) => tx.$executeRaw`SELECT authz.unshare('ticket', ${id}::text, 'cc', 'user', ${user}::text)`);
  return noContent();
});

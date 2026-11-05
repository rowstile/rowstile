// The vendor's staff, where the workspace lets them in: responder on the ticket for an hour, on the record and
// announced (authz.break_glass). Without support access, a 403.
import { route } from "@rowstile/next";
import { inTx } from "@/db.ts";
import { body, noContent } from "@/http.ts";

type Params = { params: Promise<{ id: string }> };

export const POST = route(async (req: Request, { params }: Params) => {
  const { id } = await params;
  const { reason } = await body<{ reason: string }>(req);
  await inTx((tx) => tx.$executeRaw`SELECT authz.break_glass('ticket', ${id}::text, 'responder', ${reason}, interval '1 hour')`);
  return noContent();
});

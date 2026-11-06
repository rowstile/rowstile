// The vendor's staff, where the workspace lets them in: responder on the ticket for an hour (or for the seconds the
// request asks, an hour at most), on the record and announced (authz.break_glass). Without support access, a 403.
// When it ends, the database refuses them at once; the ticket leaves their live shapes at the next
// authz.sync_tick() (jobs/sync-tick.ts).
import { route } from "@rowstile/next";
import { inTx } from "@/db.ts";
import { body, noContent } from "@/http.ts";

type Params = { params: Promise<{ id: string }> };

export const POST = route(async (req: Request, { params }: Params) => {
  const { id } = await params;
  const { reason, seconds = 3600 } = await body<{ reason: string; seconds?: number }>(req);
  const lasts = Math.min(Math.max(Math.trunc(Number(seconds)) || 3600, 1), 3600);
  await inTx((tx) => tx.$executeRaw`SELECT authz.break_glass('ticket', ${id}::text, 'responder', ${reason}, make_interval(secs => ${lasts}::int))`);
  return noContent();
});
